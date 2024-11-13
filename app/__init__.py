from flask import Flask, g, redirect, session, url_for, request
from peewee import SqliteDatabase
from config import DATABASE
from flask_mail import Mail  # Import Flask-Mail

# Initialize the Peewee database
db = SqliteDatabase(DATABASE)

app = Flask(__name__)
app.config.from_object("config")

# List of route names that don’t require authentication
excluded_routes = {
    "auth.login",
    "auth.register",
    "auth.verify_otp",
    "auth.forgot_password",
    # "auth.reset_password",
    # "auth.resend_otp",
}

mail = Mail(app)  # Initialize Flask-Mail with the app

from app import routes
from app.auth import auth_bp  # Importing auth blueprint

app.register_blueprint(auth_bp)  # Registering the auth blueprint

# Import the models after initializing the app
from app.models import User, AnalysisReport

# Create tables if they don't exist
with app.app_context():
    db.connect()
    db.create_tables([User, AnalysisReport], safe=True)
    db.close()


@app.before_request
def check_authentication():
    # Skip authentication for static files and excluded routes
    if request.endpoint.startswith("static") or request.endpoint in excluded_routes:
        return  # Allow static files and excluded routes

    # Redirect to login if user is not authenticated
    if "user_id" not in session:
        return redirect(url_for("auth.login"))


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = db
    g.db.connect()


@app.teardown_request
def teardown_request(exception):
    """Close the database connection after each request."""
    if hasattr(g, "db"):
        g.db.close()
