# app/models.py
from peewee import (
    Model,
    CharField,
    ForeignKeyField,
    TextField,
    DateTimeField,
    AutoField,
    IntegerField,
)
from datetime import datetime
from . import db


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    user_id = AutoField()
    first_name = CharField()
    last_name = CharField()
    email = CharField(unique=True)
    password = CharField()

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class AnalysisReport(BaseModel):
    report_id = AutoField()
    user = ForeignKeyField(User, backref="reports", on_delete="CASCADE")
    report_content = TextField()
    file_name = CharField()  # Add the file name
    file_size = IntegerField()  # Add the file size
    upload_time = DateTimeField(default=datetime.now)  # Add the upload time
    status = CharField()  # Add the status (Benign, Suspicious, Malicious, etc.)
    score = IntegerField()  # Add the score
    timestamp = DateTimeField(default=datetime.now)

    def __str__(self):
        return (
            f"Report {self.report_id} for {self.user.first_name} {self.user.last_name}"
        )


# Function to save analysis to the database
def save_analysis_to_db(
    file_name,
    file_path,
    file_size,
    upload_time,
    user,
    md5,
    ransomware_features,
    status,
    score,
):
    AnalysisReport.create(
        user=user,
        report_content=f"File: {file_name}\nPath: {file_path}\nSize: {file_size}\nFeatures: {ransomware_features}\nStatus: {status}\nScore: {score}",
        timestamp=upload_time,
    )


# Function to check if file has already been uploaded (based on md5 hash)
def is_file_already_uploaded(md5_hash):
    return (
        AnalysisReport.select()
        .where(AnalysisReport.report_content.contains(md5_hash))
        .exists()
    )


# Function to check if file has already been analyzed (based on md5 hash)
def is_file_analyzed(md5_hash):
    return (
        AnalysisReport.select()
        .where(AnalysisReport.report_content.contains(md5_hash))
        .exists()
    )
