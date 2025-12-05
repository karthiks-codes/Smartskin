from flask import Blueprint, request, jsonify
import os
import datetime
import base64
from models.skincare_recommender import SkincareRecommender
from models.ingredients_analyzer import IngredientsAnalyzer
from models.routine_recommender import RoutineRecommender
from models.user import User
import jwt

# Create blueprint for API routes
api = Blueprint('api', __name__)

# Initialize User model
user_model = User()

# Define file paths
data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'cosmetic_p.csv')
models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'trained')

# Initialize models lazily only when needed
recommender = None
analyzer = None
routine_recommender = None

def get_recommender():
    global recommender
    if recommender is None:
        try:
            print(f"Initializing recommender with data from: {data_path}")
            recommender = SkincareRecommender(data_path)
            print("✓ Recommender initialized successfully")
        except Exception as e:
            print(f"Error initializing recommender: {e}")
            # Try to create with a dummy path
            recommender = SkincareRecommender("dummy_path.csv")
    return recommender

def get_analyzer():
    global analyzer
    if analyzer is None:
        try:
            analyzer = IngredientsAnalyzer(models_dir)
            print("✓ Analyzer initialized successfully")
        except Exception as e:
            print(f"Error initializing analyzer: {e}")
            # Create with default models_dir to ensure it works with dummy models
            analyzer = IngredientsAnalyzer("./")
    return analyzer

def get_routine_recommender():
    global routine_recommender
    if routine_recommender is None:
        try:
            routine_data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'routine_data.csv')
            routine_recommender = RoutineRecommender(data_path=routine_data_path, model_path=models_dir)
            print("✓ Routine recommender initialized successfully")
        except Exception as e:
            print(f"Error initializing routine recommender: {e}")
            # Create with fallback paths
            routine_recommender = RoutineRecommender(data_path="dummy_path.csv", model_path="./")
    return routine_recommender

@api.route('/recommender/metadata', methods=['GET'])
def get_metadata():
    """Get all metadata needed for the recommendation form."""
    try:
        rec = get_recommender()
        return jsonify({
            'skin_types': rec.get_skin_types(),
            'categories': rec.get_categories(),
            'skin_concerns': rec.get_skin_concerns(),
            'common_ingredients': rec.get_common_ingredients()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/recommender/recommendations', methods=['POST'])
def get_recommendations():
    """Get product recommendations based on user preferences."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Get current user if authenticated
        email = get_current_user(request)
        user_feedback = None
        user_history = None
        
        # If user is authenticated, get their feedback and history for personalization
        if email:
            feedback_result, _ = user_model.get_user_feedback(email)
            user_feedback = feedback_result.get('feedback', [])
            
            history_result, _ = user_model.get_product_history(email)
            user_history = history_result.get('product_history', [])
        
        # Validate input data
        user_prefs = {
            'skin_type': data.get('skin_type', 'Normal'),
            'skin_concerns': data.get('skin_concerns', []),
            'preferred_ingredients': data.get('preferred_ingredients', []),
            'allergies': data.get('allergies', []),
            'preferred_categories': data.get('preferred_categories', [])
        }
        
        rec = get_recommender()
        recommendations = rec.get_recommendations(
            user_prefs=user_prefs,
            user_feedback=user_feedback,
            user_history=user_history
        )
        
        # If user is authenticated, update their product history with these recommendations
        if email and data.get('update_history', True):
            for product in recommendations:
                history_data = {
                    'product_id': product['id'],
                    'product_name': product['name'],
                    'category': product['label']
                }
                user_model._update_product_history(email, history_data)
        
        return jsonify({'recommendations': recommendations})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/analyzer/analyze', methods=['POST'])
def analyze_image():
    """Analyze a product image to extract ingredients and predict suitability."""
    if 'image' not in request.json:
        return jsonify({'error': 'No image provided', 'success': False}), 400
    
    try:
        # Get base64 encoded image from request
        image_data = base64.b64decode(request.json['image'].split(',')[1] if ',' in request.json['image'] else request.json['image'])
        
        # Get analyzer instance
        a = get_analyzer()
        
        # Check if models are loaded
        if not a.models_loaded:
            return jsonify({
                'success': False,
                'error': 'Models not loaded. Please ensure that the ML models are properly installed.'
            }), 503
        
        # Analyze the image
        result = a.analyze_image(image_data)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@api.route('/analyzer/ingredients', methods=['POST'])
def analyze_ingredients_text():
    """Analyze ingredients text to predict suitability for different skin types."""
    if 'ingredients' not in request.json:
        return jsonify({'error': 'No ingredients text provided', 'success': False}), 400
    
    try:
        ingredients_text = request.json['ingredients']
        
        # Get analyzer instance
        a = get_analyzer()
        
        # Check if models are loaded
        if not a.models_loaded:
            print("Warning: Models not loaded in analyzer")
            return jsonify({
                'success': False,
                'error': 'Models not loaded. Please ensure that the ML models are properly installed.',
                'details': 'Check if the model files exist in the models/trained directory'
            }), 503
        
        # Analyze ingredients text
        suitability_scores = a.predict_suitability(ingredients_text)
        
        if "error" in suitability_scores:
            print(f"Error in prediction: {suitability_scores['error']}")
            return jsonify({
                'success': False,
                'error': suitability_scores["error"],
                'details': 'There was an error processing the ingredients text'
            }), 500
        
        # Find the most suitable skin type
        best_skin_type = max(suitability_scores.items(), key=lambda x: x[1])
        
        return jsonify({
            'success': True,
            'suitability_scores': suitability_scores,
            'best_for': best_skin_type[0],
            'best_score': best_skin_type[1]
        })
    
    except Exception as e:
        print(f"Unexpected error in analyze_ingredients_text: {str(e)}")
        return jsonify({
            'error': f"Failed to analyze ingredients: {str(e)}", 
            'success': False,
            'details': 'An unexpected error occurred while processing your request'
        }), 500

@api.route('/routine/metadata', methods=['GET'])
def get_routine_metadata():
    """Get all metadata needed for the routine recommendation form."""
    try:
        routine_rec = get_routine_recommender()
        routine_metadata = {
            'skin_types': routine_rec.skin_types,
            'skin_concerns': routine_rec.skin_concerns,
            'climate_options': list(routine_rec.weather_adaptations.keys())
        }
        return jsonify(routine_metadata)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/routine/recommendations', methods=['POST'])
def get_routine_recommendations():
    """Get personalized skincare routine based on user preferences."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Validate input data
        user_data = {
            'skin_type': data.get('skin_type', 'Normal'),
            'skin_concerns': data.get('skin_concerns', []),
            'allergies': data.get('allergies', []),
            'climate': data.get('climate', 'mild'),
            'age': data.get('age', 30)
        }
        
        # Get skincare routine
        routine_rec = get_routine_recommender()
        routine = routine_rec.get_personalized_routine(user_data)
        
        # If product recommendations requested, add them to the routine
        if data.get('include_products', True):
            rec = get_recommender()
            df = rec.df
            routine = routine_rec.get_product_recommendations(routine, df)
        
        return jsonify({
            'success': True,
            'routine': routine,
            'user_data': user_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@api.route('/auth/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.json
    
    if not data or not all(k in data for k in ('email', 'password', 'name')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        result, status_code = user_model.register(
            email=data['email'],
            password=data['password'],
            name=data['name']
        )
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/auth/login', methods=['POST'])
def login():
    """Login user."""
    data = request.json
    
    if not data or not all(k in data for k in ('email', 'password')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        result, status_code = user_model.login(
            email=data['email'],
            password=data['password']
        )
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/auth/request-reset', methods=['POST'])
def request_password_reset():
    """Request a password reset link."""
    data = request.json
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    try:
        result, status_code = user_model.generate_reset_token(data['email'])
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password using a token."""
    data = request.json
    
    if not data or not all(k in data for k in ('token', 'newPassword')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        result, status_code = user_model.reset_password(
            token=data['token'],
            new_password=data['newPassword']
        )
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/auth/verify', methods=['POST'])
def verify_token():
    """Verify JWT token."""
    data = request.json
    
    if not data or 'token' not in data:
        return jsonify({'error': 'No token provided'}), 400
    
    try:
        result = user_model.verify_token(data['token'])
        if isinstance(result, dict) and 'error' in result:
            return jsonify(result), 401
        return jsonify({'valid': True, 'user': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Auth-related helper functions
def extract_token(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    return auth_header.split(' ')[1]

def get_current_user(request):
    token = extract_token(request)
    if not token:
        return None
    
    payload = user_model.verify_token(token)
    if isinstance(payload, dict) and 'error' in payload:
        return None
    
    return payload.get('email')

# Profile Endpoints
@api.route('/user/profile', methods=['GET'])
def get_profile():
    """Get user profile information."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    try:
        user_profile, status_code = user_model.get_user_profile(email)
        return jsonify(user_profile), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/user/preferences', methods=['PUT'])
def update_preferences():
    """Update user preferences."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    try:
        result, status_code = user_model.update_preferences(email, data)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Routine Endpoints
@api.route('/user/routines', methods=['GET'])
def get_user_routines():
    """Get user saved routines."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    try:
        result, status_code = user_model.get_routines(email)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/user/routines', methods=['POST'])
def save_user_routine():
    """Save a routine for the user."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    try:
        result, status_code = user_model.save_routine(email, data)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Feedback Endpoints
@api.route('/user/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback for a product recommendation."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    if not data or not all(k in data for k in ('product_id', 'product_name')):
        return jsonify({"error": "Missing required product information"}), 400
    
    try:
        result, status_code = user_model.save_product_feedback(email, data)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/user/feedback', methods=['GET'])
def get_feedback():
    """Get all feedback provided by the user."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    try:
        result, status_code = user_model.get_user_feedback(email)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/user/history', methods=['GET'])
def get_history():
    """Get the user's product viewing history."""
    email = get_current_user(request)
    if not email:
        return jsonify({"error": "Authentication required"}), 401
    
    limit = request.args.get('limit', 20, type=int)
    
    try:
        result, status_code = user_model.get_product_history(email, limit)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500 