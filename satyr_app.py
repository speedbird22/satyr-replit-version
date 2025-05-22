import os
import secrets
import logging
import json
import http.client
from typing import Optional, Dict
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from functools import wraps
import requests
import pyrebase

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database setup
class Base(DeclarativeBase):
    pass

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(16))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Firebase configuration
firebase_config = {
    "apiKey": os.environ.get("FIREBASE_API_KEY"),
    "authDomain": os.environ.get("AUTH_DOMAIN"),
    "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
    "appId": os.environ.get("FIREBASE_APP_ID"),
    "databaseURL": f"https://{os.environ.get('FIREBASE_PROJECT_ID', 'satyr-fe4f3')}-default-rtdb.firebaseio.com",
    "storageBucket": f"{os.environ.get('FIREBASE_PROJECT_ID', 'satyr-fe4f3')}.appspot.com",
    "messagingSenderId": "123456789012"
}

# Initialize Firebase
firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()
firebase_db = firebase.database()

# SATyr AI Chatbot Class
class SATyrAI:
    def __init__(self):
        self.api_key = os.environ.get("PERSONAL_AI_API_KEY", "rzZknlckhFldf2YV2AcpHlxmknkcL7Bo")
        self.domain = os.environ.get("PERSONAL_AI_DOMAIN", "km-pfrdhsi")
        self.base_url = "api.personal.ai"
        self.session_id = None
        self.user_name = None
        self.context = None
        self.conn = None
        # Initialize connection
        self._init_connection()
    
    def _init_connection(self):
        try:
            self.conn = http.client.HTTPSConnection(self.base_url, timeout=30)
        except Exception as e:
            logger.error(f"Error initializing connection: {str(e)}")
            raise

    def __del__(self):
        if hasattr(self, 'conn') and self.conn:
            try:
                self.conn.close()
            except Exception as e:
                logger.error(f"Error closing connection: {str(e)}")

    def _create_payload(self, text: str, context: Optional[str] = None) -> Dict:
        payload = {
            "Text": text,
            "DomainName": self.domain,
            "UserName": self.user_name or "Guest"
        }
        if context:
            payload["Context"] = context
        if self.session_id:
            payload["SessionId"] = self.session_id
        return payload

    def _log_api_error(self, status: int, reason: str, response_body: str) -> str:
        error_details = (
            f"API Error: {status} {reason}\n"
            f"Response: {response_body[:1000]}\n"
            f"Domain: {self.domain}\n"
            f"API Key (first 4 chars): {self.api_key[:4]}...\n"
            "Troubleshooting:\n"
            "- Check if API key is valid and not expired.\n"
            "- Verify domain is correct for your Personal AI account.\n"
            "- Ensure network connectivity and no firewall is blocking api.personal.ai.\n"
            "- Check for rate limits (HTTP 429) or server issues (HTTP 500)."
        )
        return error_details

    def send_request(self, text: str, context: Optional[str] = None) -> str:
        if not text or not isinstance(text, str) or not text.strip():
            return "[Error] Invalid or empty input text"

        # Ensure connection is open
        if not self.conn:
            self._init_connection()

        try:
            payload = json.dumps(self._create_payload(text, context))
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': self.api_key
            }

            self.conn.request("POST", "/v1/message", payload, headers)
            response = self.conn.getresponse()
            response_data = response.read().decode()

            if response.status == 200:
                try:
                    data = json.loads(response_data)
                    self.session_id = data.get("SessionId", self.session_id)
                    self.context = data.get("ai_message", "[Error] No AI message in response")
                    return self.context
                except json.JSONDecodeError as e:
                    error_msg = f"Invalid JSON response: {response_data[:100]}...{str(e)}"
                    logger.error(error_msg)
                    return f"[Error] Invalid JSON response: {str(e)}"
            else:
                error_details = self._log_api_error(response.status, response.reason, response_data)
                logger.error(error_details)
                return f"[Error] API request failed: {response.status} {response.reason}"

        except ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            logger.error(error_msg)
            # Try to reinitialize connection for next request
            try:
                self.conn.close()
            except:
                pass
            self._init_connection()
            return f"[Error] Connection error: {str(e)}"
        
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            return f"[Error] An unexpected error occurred: {str(e)}"

# 20 Amazing Themes for Your Chatbot
THEMES = {
    "satyr_classic": {
        "name": "SATyr Classic",
        "background": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        "sidebar": "linear-gradient(180deg, #1a0b3d 0%, #2d1b69 100%)",
        "text_color": "#ffffff"
    },
    "ocean_breeze": {
        "name": "Ocean Breeze",
        "background": "linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)",
        "sidebar": "linear-gradient(180deg, #0c3547 0%, #1565c0 100%)",
        "text_color": "#ffffff"
    },
    "sunset_glow": {
        "name": "Sunset Glow",
        "background": "linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)",
        "sidebar": "linear-gradient(180deg, #744C2E 0%, #A0522D 100%)",
        "text_color": "#ffffff"
    },
    "forest_green": {
        "name": "Forest Green",
        "background": "linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%)",
        "sidebar": "linear-gradient(180deg, #2E7D32 0%, #4CAF50 100%)",
        "text_color": "#ffffff"
    },
    "crimson_fire": {
        "name": "Crimson Fire",
        "background": "linear-gradient(135deg, #F44336 0%, #FF5722 100%)",
        "sidebar": "linear-gradient(180deg, #C62828 0%, #FF5722 100%)",
        "text_color": "#ffffff"
    },
    "cosmic_purple": {
        "name": "Cosmic Purple",
        "background": "linear-gradient(135deg, #E91E63 0%, #9C27B0 100%)",
        "sidebar": "linear-gradient(180deg, #8E24AA 0%, #E91E63 100%)",
        "text_color": "#ffffff"
    },
    "golden_hour": {
        "name": "Golden Hour",
        "background": "linear-gradient(135deg, #FBC02D 0%, #FF8F00 100%)",
        "sidebar": "linear-gradient(180deg, #F57F17 0%, #FF6F00 100%)",
        "text_color": "#1a1a1a"
    },
    "midnight_blue": {
        "name": "Midnight Blue",
        "background": "linear-gradient(135deg, #1a237e 0%, #3f51b5 100%)",
        "sidebar": "linear-gradient(180deg, #0d1421 0%, #1a237e 100%)",
        "text_color": "#ffffff"
    },
    "emerald_city": {
        "name": "Emerald City",
        "background": "linear-gradient(135deg, #00695c 0%, #4db6ac 100%)",
        "sidebar": "linear-gradient(180deg, #004d40 0%, #00695c 100%)",
        "text_color": "#ffffff"
    },
    "rose_gold": {
        "name": "Rose Gold",
        "background": "linear-gradient(135deg, #f06292 0%, #ffb74d 100%)",
        "sidebar": "linear-gradient(180deg, #c2185b 0%, #f06292 100%)",
        "text_color": "#ffffff"
    },
    "arctic_frost": {
        "name": "Arctic Frost",
        "background": "linear-gradient(135deg, #b3e5fc 0%, #e1f5fe 100%)",
        "sidebar": "linear-gradient(180deg, #0277bd 0%, #4fc3f7 100%)",
        "text_color": "#1a1a1a"
    },
    "volcano_orange": {
        "name": "Volcano Orange",
        "background": "linear-gradient(135deg, #ff5722 0%, #ff9800 100%)",
        "sidebar": "linear-gradient(180deg, #d84315 0%, #ff5722 100%)",
        "text_color": "#ffffff"
    },
    "lavender_fields": {
        "name": "Lavender Fields",
        "background": "linear-gradient(135deg, #9c27b0 0%, #e1bee7 100%)",
        "sidebar": "linear-gradient(180deg, #7b1fa2 0%, #9c27b0 100%)",
        "text_color": "#ffffff"
    },
    "neon_nights": {
        "name": "Neon Nights",
        "background": "linear-gradient(135deg, #00e676 0%, #1de9b6 100%)",
        "sidebar": "linear-gradient(180deg, #00c853 0%, #00e676 100%)",
        "text_color": "#1a1a1a"
    },
    "cherry_blossom": {
        "name": "Cherry Blossom",
        "background": "linear-gradient(135deg, #f8bbd9 0%, #fce4ec 100%)",
        "sidebar": "linear-gradient(180deg, #e91e63 0%, #f8bbd9 100%)",
        "text_color": "#1a1a1a"
    },
    "steel_gray": {
        "name": "Steel Gray",
        "background": "linear-gradient(135deg, #607d8b 0%, #90a4ae 100%)",
        "sidebar": "linear-gradient(180deg, #37474f 0%, #607d8b 100%)",
        "text_color": "#ffffff"
    },
    "tropical_paradise": {
        "name": "Tropical Paradise",
        "background": "linear-gradient(135deg, #00bcd4 0%, #80deea 100%)",
        "sidebar": "linear-gradient(180deg, #00838f 0%, #00bcd4 100%)",
        "text_color": "#ffffff"
    },
    "galaxy_space": {
        "name": "Galaxy Space",
        "background": "linear-gradient(135deg, #3f51b5 0%, #9c27b0 100%)",
        "sidebar": "linear-gradient(180deg, #1a237e 0%, #3f51b5 100%)",
        "text_color": "#ffffff"
    },
    "royal_purple": {
        "name": "Royal Purple",
        "background": "linear-gradient(135deg, #673ab7 0%, #9c27b0 100%)",
        "sidebar": "linear-gradient(180deg, #4527a0 0%, #673ab7 100%)",
        "text_color": "#ffffff"
    },
    "electric_blue": {
        "name": "Electric Blue",
        "background": "linear-gradient(135deg, #2196f3 0%, #21cbf3 100%)",
        "sidebar": "linear-gradient(180deg, #1565c0 0%, #2196f3 100%)",
        "text_color": "#ffffff"
    }
}

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to refresh user token
def refresh_user_token(refresh_token):
    try:
        response = requests.post(
            'https://securetoken.googleapis.com/v1/token?key=' + os.environ.get("FIREBASE_API_KEY"),
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }
        )
        if response.status_code == 200:
            data = response.json()
            new_id_token = data.get('id_token')
            new_refresh_token = data.get('refresh_token')
            if new_id_token:
                session['user_token'] = new_id_token
                session['refresh_token'] = new_refresh_token
                return new_id_token
            else:
                flash("Failed to obtain new ID token from refresh response.", "error")
                return None
        else:
            flash(f"Failed to refresh token: {response.text}", "error")
            return None
    except Exception as e:
        flash(f"Error refreshing token: {str(e)}", "error")
        return None

# Routes
@app.route('/')
def index():
    # Redirect to the new website home page
    return redirect(url_for('website_home'))

@app.route('/website')
def website_home():
    # Increment visit counter if it exists, otherwise initialize to 1
    if 'visit_count' in session:
        session['visit_count'] = session['visit_count'] + 1
    else:
        session['visit_count'] = 1
    
    return render_template(
        'website_home.html', 
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES,
        visit_count=session.get('visit_count', 0)
    )

@app.route('/website/games')
def website_games():
    return render_template(
        'mindtale.html',
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )

@app.route('/website/notes')
def website_notes():
    return render_template(
        'work_in_progress.html',
        page_title="Notes",
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )

@app.route('/website/friends')
def website_friends():
    return render_template(
        'work_in_progress.html',
        page_title="Friends",
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )

@app.route('/website/settings')
def website_settings():
    return render_template(
        'website_settings.html',
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Authenticate with Firebase
            user = auth.sign_in_with_email_and_password(email, password)
            
            # Store user data in session
            session['user_token'] = user['idToken']
            session['refresh_token'] = user['refreshToken']
            session['user_id'] = user['localId']
            session['user_email'] = email
            
            # Get user info
            user_info = firebase_db.child("users").child(user['localId']).get(token=user['idToken'])
            if user_info.val():
                session['user_name'] = user_info.val().get('username', 'User')
            
            flash('Login successful!', 'success')
            return redirect(url_for('chat'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            error_message = "Invalid email or password. Please try again."
            flash(error_message, 'error')
    
    return render_template(
        'login.html',
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Create user with Firebase
            user = auth.create_user_with_email_and_password(email, password)
            
            # Send email verification
            auth.send_email_verification(user['idToken'])
            
            # Store user data in database
            user_data = {
                "username": username,
                "email": email
            }
            
            firebase_db.child("users").child(user['localId']).set(user_data, token=user['idToken'])
            
            flash('Account created successfully! Please verify your email before logging in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            error_message = "An error occurred during signup."
            if "EMAIL_EXISTS" in str(e):
                error_message = "Email already exists. Please use a different email or login."
            elif "WEAK_PASSWORD" in str(e):
                error_message = "Password is too weak. Please use at least 6 characters."
            
            flash(error_message, 'error')
            return redirect(url_for('signup'))
    
    return render_template(
        'signup.html',
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=session.get('theme', 'satyr_stock'),
        themes=THEMES
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Send password reset email via Firebase"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        # Send password reset email using Firebase
        auth.send_password_reset_email(email)
        
        return jsonify({
            'success': True, 
            'message': 'Password reset email sent! Check your inbox.'
        })
        
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return jsonify({
            'success': False, 
            'message': 'Failed to send reset email. Please check the email address.'
        })

@app.route('/save_conversation', methods=['POST'])
@login_required
def save_conversation():
    """Save conversation to PostgreSQL database"""
    try:
        data = request.get_json()
        messages = data.get('messages', [])
        conversation_title = data.get('title', 'New Conversation')
        
        user_data = session.get('user_data', {})
        user_email = user_data.get('email')
        
        if not user_email:
            return jsonify({'success': False, 'message': 'User not authenticated'})
        
        # For now, store in session until we set up proper database
        if 'conversations' not in session:
            session['conversations'] = []
        
        conversation = {
            'id': len(session['conversations']) + 1,
            'title': conversation_title,
            'messages': messages,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        session['conversations'].append(conversation)
        session.modified = True
        
        return jsonify({'success': True, 'conversation_id': conversation['id']})
        
    except Exception as e:
        logger.error(f"Save conversation error: {e}")
        return jsonify({'success': False, 'message': 'Failed to save conversation'})

@app.route('/get_conversations', methods=['GET'])
@login_required
def get_conversations():
    """Get user's conversation history"""
    try:
        conversations = session.get('conversations', [])
        return jsonify({'success': True, 'conversations': conversations})
    except Exception as e:
        logger.error(f"Get conversations error: {e}")
        return jsonify({'success': False, 'message': 'Failed to load conversations'})

@app.route('/ai')
@login_required
def ai_chat():
    # Beautiful chatbot interface - requires authentication
    user_data = session.get('user_data', {})
    return render_template('ai_chat_simple.html', user_data=user_data)

@app.route('/chat')
@login_required
def chat():
    # Initialize chatbot if not already done
    if 'chatbot' not in session:
        try:
            session['chatbot'] = True  # Flag that chatbot is initialized - actual instance will be server-side
        except Exception as e:
            logger.error(f"Error initializing chatbot: {str(e)}")
            flash('Error initializing chat service.', 'error')
    
    # Load chat history
    chat_history = []
    try:
        # Get chat history from database
        user_id = session.get('user_id')
        if user_id:
            user_token = session.get('user_token')
            history_data = firebase_db.child("chat_history").child(user_id).get(token=user_token)
            
            if history_data.val():
                if isinstance(history_data.val(), list):
                    chat_history = history_data.val()
                elif isinstance(history_data.val(), dict):
                    chat_history = history_data.val().get('messages', [])
    except Exception as e:
        logger.error(f"Error loading chat history: {str(e)}")
        flash('Could not load chat history.', 'warning')
    
    # Get current theme data
    current_theme_name = session.get('theme', 'satyr_classic')
    current_theme = THEMES.get(current_theme_name, THEMES['satyr_classic'])
    
    # Use the AI chat template with website layout
    return render_template(
        'ai_chat_simple.html',
        firebase_api_key=os.environ.get("FIREBASE_API_KEY"),
        firebase_project_id=os.environ.get("FIREBASE_PROJECT_ID"),
        firebase_app_id=os.environ.get("FIREBASE_APP_ID"),
        auth_domain=os.environ.get("AUTH_DOMAIN"),
        current_theme=current_theme,
        themes=THEMES,
        chat_history=chat_history,
        username=session.get('username', 'User'),
        user_email=session.get('user_email', 'user@example.com')
    )

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message.strip():
            return jsonify({'error': 'Empty message'}), 400
        
        # Initialize SATyr AI with your credentials
        satyr_ai = SATyrAI()
        satyr_ai.user_name = session.get('username', 'User')
        
        # Get AI response using your Personal AI implementation
        ai_response = satyr_ai.send_request(user_message)
        
        return jsonify({
            'response': ai_response,
            'user_message': user_message
        })
        
    except Exception as e:
        app.logger.error(f"Error in send_message: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/set_theme', methods=['POST'])
@login_required
def set_theme():
    theme = request.json.get('theme', 'satyr_stock')
    session['theme'] = theme
    
    # Save theme preference to Firebase
    try:
        user_id = session.get('user_id')
        user_token = session.get('user_token')
        
        if user_id and user_token:
            user_data = firebase_db.child("users").child(user_id).get(token=user_token).val() or {}
            user_data['preferred_theme'] = theme
            firebase_db.child("users").child(user_id).update(user_data, token=user_token)
    except Exception as e:
        logger.error(f"Error saving theme preference: {str(e)}")
    
    return jsonify({'status': 'success', 'theme': theme})

@app.route('/update_username', methods=['POST'])
@login_required
def update_username():
    new_username = request.json.get('username', '')
    if not new_username:
        return jsonify({'error': 'Username cannot be empty'}), 400
    
    try:
        user_id = session.get('user_id')
        user_token = session.get('user_token')
        
        if user_id and user_token:
            # Update username in database
            user_data = firebase_db.child("users").child(user_id).get(token=user_token).val() or {}
            user_data['username'] = new_username
            firebase_db.child("users").child(user_id).update(user_data, token=user_token)
            
            # Update session
            session['user_name'] = new_username
            
            return jsonify({'status': 'success', 'username': new_username})
        else:
            return jsonify({'error': 'User not authenticated'}), 401
    
    except Exception as e:
        logger.error(f"Error updating username: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/get_chat_history', methods=['GET'])
@login_required
def get_chat_history():
    try:
        user_id = session.get('user_id')
        user_token = session.get('user_token')
        
        if user_id and user_token:
            history_data = firebase_db.child("chat_history").child(user_id).get(token=user_token)
            messages = []
            if history_data.val() and history_data.val().get('messages'):
                messages = history_data.val().get('messages', [])
            
            return jsonify({'status': 'success', 'chat_history': messages})
        else:
            return jsonify({'error': 'User not authenticated'}), 401
    
    except Exception as e:
        logger.error(f"Error getting chat history: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/clear_chat_history', methods=['POST'])
@login_required
def clear_chat_history():
    try:
        user_id = session.get('user_id')
        user_token = session.get('user_token')
        
        if user_id and user_token:
            # Clear chat history in database
            firebase_db.child("chat_history").child(user_id).remove(token=user_token)
            
            return jsonify({'status': 'success'})
        else:
            return jsonify({'error': 'User not authenticated'}), 401
    
    except Exception as e:
        logger.error(f"Error clearing chat history: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/reset_account', methods=['POST'])
@login_required
def reset_account():
    try:
        user_id = session.get('user_id')
        user_token = session.get('user_token')
        
        if user_id and user_token:
            # Clear chat history in database
            firebase_db.child("chat_history").child(user_id).remove(token=user_token)
            
            # Log user out
            session.clear()
            
            return jsonify({'status': 'success'})
        else:
            return jsonify({'error': 'User not authenticated'}), 401
    
    except Exception as e:
        logger.error(f"Error resetting account: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)