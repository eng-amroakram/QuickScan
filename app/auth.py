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
                session["user_id"] = user.user_id
                session["email"] = user.email
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
            session["user_id"] = new_user.user_id
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


@auth_bp.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        try:
            user = User.get(User.email == email)
            # Generate OTP
            otp = generate_otp()

            # Store OTP in the session or in a database if required
            session["otp"] = otp
            session["reset_user_id"] = user.user_id

            # Send OTP via email
            msg = Message(
                subject="Your Password Reset OTP for QuickScan",
                recipients=[email],
                body=f"Hello,\n\nYour OTP for password reset is: {otp}\n\nUse this OTP to reset your password.\n\nBest regards,\nQuickScan Team",
            )
            mail.send(msg)
            flash("An OTP has been sent to your email to reset your password.")
            return redirect(url_for("auth.reset_password"))
        except User.DoesNotExist:
            flash("Email not found. Please register first.")
            return redirect(url_for("auth.register"))

    return render_template("admin/auth/forgot_password.html")


@auth_bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        new_password = request.form["password"]
        reset_user_id = session.get("reset_user_id")
        correct_otp = session.get("otp")

        if entered_otp == correct_otp and reset_user_id:
            # Hash the new password
            hashed_password = generate_password_hash(new_password)
            # Update the user’s password in the database
            user = User.get_by_id(reset_user_id)
            user.password = hashed_password
            user.save()

            # Clear the OTP from the session
            session.pop("otp", None)
            session.pop("reset_user_id", None)

            flash("Your password has been reset successfully.")
            return redirect(url_for("auth.login"))
        else:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for("auth.reset_password"))

    return render_template("admin/auth/reset_password.html")


@auth_bp.route("/resend_otp", methods=["GET"])
def resend_otp():
    user_id = session.get("reset_user_id")

    # Check if the user is logged in and has started registration
    if not user_id:
        flash("You need to register or log in first.")
        return redirect(url_for("auth.register"))

    try:
        # Retrieve the user from the database
        user = User.get(User.user_id == user_id)

        # Generate a new OTP
        otp = generate_otp()

        # Send OTP email
        msg = Message(
            subject="Your OTP for QuickScan Registration",
            recipients=[user.email],
            body=f"Hello {user.first_name},\n\nYour new OTP for QuickScan registration is: {otp}\n\nPlease use this OTP to verify your account.\n\nBest regards,\nQuickScan Team",
        )
        mail.send(msg)

        # Store the new OTP in the session
        session["otp"] = otp

        flash("A new OTP has been sent to your email.")
        return redirect(url_for("auth.reset_password"))

    except Exception as e:
        flash(f"Error sending OTP: {str(e)}")
        return redirect(url_for("auth.reset_password"))


@auth_bp.route("/logout")
def logout():
    # Clear the session data
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for("auth.login"))
