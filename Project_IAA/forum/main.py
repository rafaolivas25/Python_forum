from flask import Blueprint, render_template
from flask_login import login_required
from flask import render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_required, current_user
from forum import db
from forum.models import Topic, Message
from forum.forms import TopicForm, MessageForm

main = Blueprint('main', __name__)


@main.route('/')
@main.route('/home')
@login_required
def home():
    topics = Topic.query.all()
    return render_template('home.html', title='Home', topics=topics)


@main.route("/about")
def about():
    return render_template('about.html')


@main.route('/topic/new', methods=['GET', 'POST'])
@login_required
def new_topic():
    form = TopicForm()
    if form.validate_on_submit():
        topic = Topic(title=form.title.data, user_id=current_user.id)
        db.session.add(topic)
        db.session.commit()
        flash('Your topic has been created!', 'success')
        return redirect(url_for('main.home'))
    return render_template('create_topic.html', title='New Topic', form=form)


@main.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
@login_required
def topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(content=form.content.data, user_id=current_user.id, topic_id=topic.id)
        db.session.add(message)
        db.session.commit()
        flash('Your message has been posted!', 'success')
        return redirect(url_for('main.topic', topic_id=topic.id))
    messages = Message.query.filter_by(topic_id=topic.id).all()
    return render_template('topic.html', title=topic.title, topic=topic, form=form, messages=messages)


@main.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this message.', 'danger')
        return redirect(url_for('main.topic', topic_id=message.topic_id))

    db.session.delete(message)
    db.session.commit()
    flash('Message has been deleted!', 'success')
    return redirect(url_for('main.topic', topic_id=message.topic_id))


@main.route('/topic/delete/<int:topic_id>', methods=['POST'])
@login_required
def delete_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if topic.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this topic.', 'danger')
        return redirect(url_for('main.topic', topic_id=topic.id))

    db.session.delete(topic)
    db.session.commit()
    flash('Topic has been deleted!', 'success')
    return redirect(url_for('main.home'))
