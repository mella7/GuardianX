import os
from app import app, db, User

with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id}, Full Name: {user.full_name}, Email: {user.email}")

print(f"Auth0 Domain: {os.getenv('AUTH0_DOMAIN')}")
print(f"Auth0 Client ID: {os.getenv('AUTH0_CLIENT_ID')}")
print(f"Auth0 Client Secret: {os.getenv('AUTH0_CLIENT_SECRET')}")
