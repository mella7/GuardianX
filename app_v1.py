import os, base64, requests, vulnerability_scanner, vt, time, json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User
from authlib.integrations.flask_client import OAuth


load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
app.secret_key = os.environ.get("SECRET_KEY")

# sqllite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# auth0 configuration
# app.secret_key = os.getenv("SECRET_KEY")
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///instance/users.db"
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# app.config["SESSION_COOKIE_NAME"] = "auth0_session"


db.init_app(app)

# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = "login"


with app.app_context():
    db.create_all()


oauth = OAuth(app)
auth0 = oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    api_base_url=f"https://{os.getenv('AUTH0_DOMAIN')}",
    access_token_url=f"https://{os.getenv('AUTH0_DOMAIN')}/oauth/token",
    authorize_url=f"https://{os.getenv('AUTH0_DOMAIN')}/authorize",
    client_kwargs={"scope": "openid profile email"},
)


class RateLimiter:
    """
    rate limiter class that controls the number of requests made per minute and per day.
    """

    def __init__(self, limit_per_min, limit_per_day):
        self.limit_per_min = limit_per_min
        self.limit_per_day = limit_per_day
        self.requests_per_min = {}
        self.requests_per_day = {}

    def can_make_request(self):
        """
        checks if request can be made based on current rate limits
        """
        current_time = int(time.time())
        current_day = int(time.strftime("%j"))

        # per minute limit
        if current_time - 60 not in self.requests_per_min:
            self.requests_per_min[current_time - 60] = 0
        if self.requests_per_min[current_time - 60] >= self.limit_per_min:
            return False

        # per day limit
        if current_day not in self.requests_per_day:
            self.requests_per_day[current_day] = 0
        if self.requests_per_day[current_day] >= self.limit_per_day:
            return False

        return True

    def update_requests(self):
        """
        updates the request counters after a request is made
        """
        current_time = int(time.time())
        current_day = int(time.strftime("%j"))

        # update per minute requests
        if current_time not in self.requests_per_min:
            self.requests_per_min[current_time] = 0
        self.requests_per_min[current_time] += 1

        # update per day requests
        if current_day not in self.requests_per_day:
            self.requests_per_day[current_day] = 0
        self.requests_per_day[current_day] += 1


rate_limiter = RateLimiter(limit_per_min=4, limit_per_day=500)


@app.route("/")
def index():
    return render_template("base.html")


@app.route("/scan_results")
def scan_results():
    return render_template("scan_results.html")


@app.route("/contact")
def contact_form():
    return render_template("contact.html")


@app.route("/login")
def login():  # prev. render_loginpage
    return render_template("login.html")


# auth0
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


# @app.route("/login")
# def login():
#     return auth0.authorize_redirect(redirect_uri=os.getenv("AUTH0_CALLBACK_URL"))


# @app.route("/callback")
# def callback():
#     token = auth0.authorize_access_token()
#     user_info = auth0.parse_id_token(token)
#     user = User.query.filter_by(email=user_info["email"]).first()

#     if not user:
#         user = User(email=user_info["email"], name=user_info["name"])
#         db.session.add(user)
#         db.session.commit()


# @app.route("/logout")
# def logout():
#     session.clear()
#     return redirect(url_for("index"))


@app.route("/authenticate", methods=["GET", "POST"])
def login_auth():

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email, password=password).first()

        if user:
            # User is found, redirect to the index page

            flash("Successful login!")

            return redirect(url_for("index"))
        else:
            # User is not found, redirect back to the login page
            return redirect(url_for("render_loginpage"))


# @app.route("/register")
# def register():
#     return render_template("register.html")


@app.route("/analyze", methods=["POST"])
def analyze_url():
    """
    Handles the URL analysis requests.
    """

    url = request.form["url"]

    # Encode the URL using base64
    url_id = (
        base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    )  # Removed padding

    vulnerabilities = get_url_analysis_report(url_id)
    relevant_data = extract_relevant_data(vulnerabilities)
    return render_template(
        "scan_results.html", scanned_url=url, relevant_data=relevant_data
    )


# Add  func to handle user registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full-name")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if the user already exists
        user_exists = User.query.filter_by(email=email).first()

        if user_exists:
            flash("Email address already exists")
            return redirect(url_for("register"))

        # new user and hash the password
        new_user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(password, method="pbkdf2"),
        )

        # add user to the database
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!")
        return redirect(url_for("login"))

    return render_template("register.html")


def get_url_analysis_report(url_id):
    """
    Retrieves the analysis report for the given URL identifier.
    """
    # Construct the API URL with the URL identifier
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    # print("API URL:", api_url) debug

    # Set the headers with the API key
    headers = {"accept": "application/json", "x-apikey": API_KEY}

    # Send a GET request to retrieve the analysis report
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.json()  # Return JSON response
    else:
        return {
            "error": f"Failed to retrieve analysis report, status code: {response.status_code}"
        }


def extract_relevant_data(json_data):
    analysis_results = (
        json_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    )
    relevant_data = []
    for engine, result in analysis_results.items():
        relevant_data.append(
            {
                "engine_name": engine,
                "method": result.get("method", "N/A"),
                "category": result.get("category", "N/A"),
                "result": result.get("result", "N/A"),
            }
        )
    return relevant_data


if __name__ == "__main__":
    app.run(debug=True)
