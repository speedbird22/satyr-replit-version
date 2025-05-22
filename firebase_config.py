import pyrebase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Validate required environment variables
required_env_vars = [
    "API_KEY", "AUTH_DOMAIN", "PROJECT_ID", "STORAGE_BUCKET",
    "MESSAGING_SENDER_ID", "APP_ID", "MEASUREMENT_ID", "DATABASE_URL"
]
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}. Please check your .env file.")

# Firebase configuration
firebase_config = {
    "apiKey": os.getenv("API_KEY"),
    "authDomain": os.getenv("AUTH_DOMAIN"),
    "projectId": os.getenv("PROJECT_ID"),
    "storageBucket": os.getenv("STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("MESSAGING_SENDER_ID"),
    "appId": os.getenv("APP_ID"),
    "measurementId": os.getenv("MEASUREMENT_ID"),
    "databaseURL": os.getenv("DATABASE_URL")
}

# Initialize Firebase
firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()
db = firebase.database()
