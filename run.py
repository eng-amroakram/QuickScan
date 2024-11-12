# run.py
from app import app, db  # Import the app and db instances

if __name__ == "__main__":
    app.run(debug=True)
