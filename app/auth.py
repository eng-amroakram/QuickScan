from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from flask_mail import Message
from app import db
from app import mail  # Import Flask-Mail instance
import random
import string


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# Function to generate OTP
def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    return "".join(random.choices(string.digits, k=length))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Check if the user exists
        try:
            user = User.get(User.email == email)
            # Verify the password
            if check_password_hash(user.password, password):
                flash("Login successful.")
                # Redirect to a dashboard or home page after login
                return redirect(url_for("home"))
            else:
                flash("Incorrect password. Please try again.")
        except User.DoesNotExist:
            flash("Email not found. Please register first.")

        return redirect(url_for("auth.login"))

    return render_template("admin/auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]

        # Check if email is already registered
        if User.select().where(User.email == email).exists():
            flash("Email is already registered. Please use a different one.")
            return redirect(url_for("auth.register"))

        # Hash the password and create the user
        hashed_password = generate_password_hash(password)
        new_user = User.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
        )

        # Generate OTP
        otp = generate_otp()

        # Send OTP email
        msg = Message(
            subject="Your OTP for QuickScan Registration",
            recipients=[email],
            body=f"Hello {first_name},\n\nYour OTP for QuickScan registration is: {otp}\n\nPlease use this OTP to verify your account.\n\nBest regards,\nQuickScan Team",
        )
        try:
            mail.send(msg)
            flash("Registration successful. OTP has been sent to your email.")
            # Save the OTP to the database or session for verification during the next step
            # (Optional: save OTP to the user's record or as a session variable)
            # Here, we just store it in the session temporarily
            session["otp"] = otp
            session["user_id"] = new_user.id
            return redirect(url_for("auth.verify_otp"))
        except Exception as e:
            flash(f"Error sending OTP: {str(e)}")
            return redirect(url_for("auth.register"))

    return render_template("admin/auth/register.html")


@auth_bp.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        correct_otp = session.get("otp")

        if entered_otp == correct_otp:
            flash("OTP verified successfully!")
            # You can now mark the user as verified or proceed with login
            return redirect(url_for("auth.login"))
        else:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for("auth.verify_otp"))

    return render_template("admin/auth/verify_otp.html")
