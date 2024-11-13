from app import app
from flask import (
    render_template,
    jsonify,
    session,
    redirect,
    url_for,
    request,
    flash,
    send_file,
)
from app.models import (
    save_analysis_to_db,
    is_file_already_uploaded,
)  # Import the functions from models
import os
from datetime import datetime
import hashlib
import yara
import io

from app.models import AnalysisReport, User


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
    yara_dir = app.config["YARA_DIR"]  # Use the YARA_DIR from the config
    for rule_file in os.listdir(yara_dir):
        rule_path = os.path.join(yara_dir, rule_file)
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
    # Retrieve all reports, including the necessary fields like file_name, file_size, status, and score
    reports = (
        AnalysisReport.select().join(User).order_by(AnalysisReport.timestamp.desc())
    )

    # Pass the reports to the template
    return render_template("admin/files.html", reports=reports)


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
    file_size = os.path.getsize(file_path)  # Get file size in bytes
    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_email = session.get(
        "email", "guest@example.com"
    )  # Use email instead of user_name

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
    user = User.get(User.email == user_email)  # Get user by email
    analysis_report = AnalysisReport.create(
        user=user,
        report_content=ransomware_features,  # Add the YARA rules match as report content
        file_name=file_name,
        file_size=file_size,
        upload_time=upload_time,
        status=status,
        score=score,
    )

    # Return success response with file path
    return jsonify(
        success=True, message="File uploaded and analyzed successfully.", md5=md5_hash
    )


@app.route("/report/<int:report_id>")
def report_details(report_id):
    # Fetch the report by ID from the database
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        return redirect(url_for("files"))  # Redirect to file list page if not found

    return render_template("admin/report_details.html", report=report)


@app.route("/report/download/<int:report_id>")
def download_report(report_id):
    # Retrieve the report
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        return redirect(url_for("files"))

    # Create a text-based report for download
    report_content = f"""Report ID: {report.report_id}
File Name: {report.file_name}
File Size: {report.file_size / 1024:.2f} KB
Upload Time: {report.upload_time}
Status: {report.status}
Score: {report.score}
Ransomware Features: {report.report_content}
Generated By: {report.user.first_name} {report.user.last_name}
"""

    # Prepare the file for download
    output = io.BytesIO()
    output.write(report_content.encode("utf-8"))
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name=f"report_{report.report_id}.txt",
        mimetype="text/plain",
    )
