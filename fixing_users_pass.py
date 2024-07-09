from flask import Flask
from models import db, User
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///instance/users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    users = User.query.all()

    for user in users:
        if not user.password_hash:
            # Set a default password or handle as needed
            user.password_hash = generate_password_hash('default_password')
            db.session.add(user)

    db.session.commit()
    print("User passwords have been updated.")
