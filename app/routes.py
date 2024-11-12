from app import app
from flask import render_template, jsonify, session, redirect, url_for, request
from app.models import (
    save_analysis_to_db,
    is_file_already_uploaded,
)  # Import the functions from models
import os
from datetime import datetime
import hashlib
import yara

YARA_DIR = os.path.join(os.getcwd(), "yara")  # Directory containing YARA rules


# Calculate the MD5 hash of a file
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()


# Apply YARA rules to a file
def apply_yara_rules(file_path):
    matches = []
    for rule_file in os.listdir(YARA_DIR):
        rule_path = os.path.join(YARA_DIR, rule_file)
        if os.path.isfile(rule_path):
            rule = yara.compile(filepath=rule_path)
            rule_matches = rule.match(file_path)
            if rule_matches:
                matches.extend([match.rule for match in rule_matches])
    return matches


@app.route("/")
def home():
    return render_template(
        "admin/home.html", user_name=session.get("user_name", "Guest")
    )


@app.route("/files")
def files():
    return render_template("admin/files.html")


@app.route("/flag")
def flag():
    return render_template("admin/flag.html")


@app.route("/help")
def help():
    return render_template("admin/help.html")


@app.route("/info")
def info():
    return render_template("admin/info.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return jsonify({"success": False, "redirect": url_for("auth.login")})

    if "file" not in request.files:
        return jsonify(success=False), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify(success=False), 400

    # Ensure the upload folder exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Save the file
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    # Calculate the MD5 hash
    md5_hash = calculate_md5(file_path)

    # Check if the file has already been uploaded
    if is_file_already_uploaded(md5_hash):
        os.remove(file_path)  # Remove the duplicate file
        return jsonify(
            success=True, message="This file has already been uploaded.", md5=md5_hash
        )

    # File details
    file_name = file.filename
    file_size = os.path.getsize(file_path)
    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = session.get("user_name", "Guest")

    # Apply YARA rules
    matched_rules = apply_yara_rules(file_path)
    ransomware_features = ", ".join(matched_rules) if matched_rules else "N/A"
    matched_count = len(matched_rules)

    # Determine status and score
    if matched_count == 0:
        status = "Benign"
        score = 0
    elif matched_count == 1:
        status = "Suspicious"
        score = 30
    elif matched_count == 2:
        status = "Malicious"
        score = 70
    else:
        status = "Very Malicious"
        score = 100

    # Save the analysis to the database
    save_analysis_to_db(
        file_name,
        file_path,
        file_size,
        upload_time,
        user,
        md5_hash,
        ransomware_features,
        status,
        score,
    )

    # Return success response with file path
    return jsonify(
        success=True, message="File uploaded and analyzed successfully.", md5=md5_hash
    )
