from forum import create_app
from forum.extensions import db
from forum.models import User

app = create_app()

with app.app_context():
    user = User.query.filter_by(email='ruca@gmail.com').first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f'Role admin has been assigned to {user.username}.')
    else:
        print('User not found.')
