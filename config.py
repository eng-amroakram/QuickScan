import os


# Variables

DEBUG = True
SECRET_KEY = "your_secret_key_here"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "QuickScan.db")


# Flask-Mail configuration
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USERNAME = "testhack1973@gmail.com"
MAIL_PASSWORD = "afft kphm potd tsvy"  # Remember to keep this secure
MAIL_USE_TLS = True
MAIL_DEFAULT_SENDER = ("QuickScan", "testhack1973@gmail.com")
