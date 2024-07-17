import os, base64, requests, time
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.secret_key = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Database setup
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Auth0 setup
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

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

    def __init__(self, full_name, email, password):
        self.full_name = full_name
        self.email = email
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
def login():
    return auth0.authorize_redirect(redirect_uri=os.getenv("AUTH0_CALLBACK_URL"))


@app.route("/callback")
def callback():
    token = auth0.authorize_access_token()
    user_info = auth0.parse_id_token(token)
    user = User.query.filter_by(email=user_info["email"]).first()

    if not user:
        user = User(full_name=user_info["name"], email=user_info["email"], password="")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/authenticate", methods=["GET", "POST"])
def login_auth():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Successful login!")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials!")
            return redirect(url_for("login"))

    return render_template("login.html")


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

        # Create a new user and hash the password
        new_user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(password, method="pbkdf2:sha256"),
        )

        # Add user to the database
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/analyze", methods=["POST"])
def analyze_url():
    url = request.form["url"]

    # Encode the URL using base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    vulnerabilities = get_url_analysis_report(url_id)
    relevant_data = extract_relevant_data(vulnerabilities)
    return render_template(
        "scan_results.html", scanned_url=url, relevant_data=relevant_data
    )


def get_url_analysis_report(url_id):
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to retrieve analysis report, status code: {response.status_code}"}


def extract_relevant_data(json_data):
    analysis_results = json_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    relevant_data = [
        {
            "engine_name": engine,
            "method": result.get("method", "N/A"),
            "category": result.get("category", "N/A"),
            "result": result.get("result", "N/A"),
        }
        for engine, result in analysis_results.items()
    ]
    return relevant_data


class RateLimiter:
    def __init__(self, limit_per_min, limit_per_day):
        self.limit_per_min = limit_per_min
        self.limit_per_day = limit_per_day
        self.requests_per_min = {}
        self.requests_per_day = {}

    def can_make_request(self):
        current_time = int(time.time())
        current_day = int(time.strftime("%j"))

        if current_time - 60 not in self.requests_per_min:
            self.requests_per_min[current_time - 60] = 0
        if self.requests_per_min[current_time - 60] >= self.limit_per_min:
            return False

        if current_day not in self.requests_per_day:
            self.requests_per_day[current_day] = 0
        if self.requests_per_day[current_day] >= self.limit_per_day:
            return False

        return True

    def update_requests(self):
        current_time = int(time.time())
        current_day = int(time.strftime("%j"))

        if current_time not in self.requests_per_min:
            self.requests_per_min[current_time] = 0
        self.requests_per_min[current_time] += 1

        if current_day not in self.requests_per_day:
            self.requests_per_day[current_day] = 0
        self.requests_per_day[current_day] += 1


rate_limiter = RateLimiter(limit_per_min=4, limit_per_day=500)


if __name__ == "__main__":
    app.run(debug=True)