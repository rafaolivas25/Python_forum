from forum.models import db, Client
from run import app

# Ensure the application context is set up
with app.app_context():
    db.create_all()  # This will create all tables if they don't exist

    client1 = Client(client_id='service1_client_id', client_secret='service1_client_secret', redirect_uri='http://localhost:5001/callback', scope='read')
    client2 = Client(client_id='service2_client_id', client_secret='service2_client_secret', redirect_uri='http://localhost:5002/callback', scope='read')
    client3 = Client(client_id='service3_client_id', client_secret='service3_client_secret', redirect_uri='http://localhost:5003/callback', scope='read')

    db.session.add(client1)
    db.session.add(client2)
    db.session.add(client3)
    db.session.commit()
    print("Clients added to the database successfully.")
