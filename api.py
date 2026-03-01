import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ais import extract_and_format_medicine_data

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-api-secret-key-change-in-prod')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-api-jwt-secret-key')

# CORS setup - Header-based auth (no cookies needed)
CORS(app, supports_credentials=False, origins=[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://api.caresyncs.tech",
    "https://caresyncs.tech",
    "https://www.caresyncs.tech"
])

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# JWT configuration - Bearer token in Authorization header (Postman friendly)
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Initialize Firebase
firebase_creds_env = os.getenv('FIREBASE_CREDENTIALS')
if firebase_creds_env:
    try:
        cred_dict = json.loads(firebase_creds_env)
        cred = credentials.Certificate(cred_dict)
    except Exception as e:
        print("Error parsing FIREBASE_CREDENTIALS env var:", e)
        cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-446ed91b3c.json")
else:
    cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-446ed91b3c.json")

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
db = firestore.client()

# ==========================================
# UTILITY FUNCTIONS
# ==========================================

def get_validated_user_id():
    """
    Get and validate user_id from X-User-Id header.
    Must match JWT identity to prevent spoofing.
    """
    jwt_identity = get_jwt_identity()
    header_user_id = request.headers.get('X-User-Id')
    
    if not header_user_id:
        raise ValueError("Missing X-User-Id header")
    if header_user_id != jwt_identity:
        raise ValueError("X-User-Id header does not match authenticated user")
    
    return header_user_id


def validate_user_id(f):
    """Decorator to validate X-User-Id header matches JWT identity."""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user_id = get_validated_user_id()
            return f(*args, **kwargs)
        except ValueError as e:
            return jsonify({"error": str(e)}), 403
    return decorated_function


def process_prescription_background(file_path, user_id, job_id):
    """Background thread function for processing prescriptions."""
    try:
        extracted_data = extract_and_format_medicine_data(file_path)
        
        # Store results in Firestore
        db.collection('ai_prescriptions').document(job_id).set({
            'user_id': user_id,
            'status': 'completed',
            'extracted_medicines': extracted_data.get('medicines', []),
            'raw_extraction': extracted_data,
            'processed_at': datetime.utcnow().isoformat(),
            'success': True
        })
    except Exception as e:
        # Store error in Firestore
        db.collection('ai_prescriptions').document(job_id).set({
            'user_id': user_id,
            'status': 'failed',
            'error': str(e),
            'processed_at': datetime.utcnow().isoformat(),
            'success': False
        })
    finally:
        # Cleanup temp file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass


def can_guardian_access_patient(guardian_id, patient_id):
    """Check if guardian has access to patient."""
    if guardian_id == patient_id:
        return True
    
    guardian_doc = db.collection('users').document(guardian_id).get()
    if not guardian_doc.exists:
        return False
    
    guardian_data = guardian_doc.to_dict()
    if not guardian_data.get('is_guardian', False):
        return False
    
    return patient_id in guardian_data.get('patients', [])


def error_response(message, code=None, status=400):
    """Return standardized error response."""
    response = {"error": message}
    if code:
        response["code"] = code
    return jsonify(response), status


def success_response(data=None, message=None, status=200):
    """Return standardized success response."""
    response = {}
    if data:
        response["data"] = data
    if message:
        response["message"] = message
    return jsonify(response), status


# ==========================================
# AUTHENTICATION API
# ==========================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def api_register():
    """Register new user with email and password."""
    try:
        data = request.get_json()
        if not data:
            data = request.form
        
        # Validate required fields
        required = ['name', 'email', 'password', 'confirm_password']
        for field in required:
            if not data.get(field):
                return error_response(f"Missing required field: {field}", status=400)
        
        # Validate password match
        if data.get('password') != data.get('confirm_password'):
            return error_response("Passwords do not match", status=400)
        
        email = data.get('email', '').strip()
        user_id = email.split('@')[0]
        
        # Check duplicate
        users_ref = db.collection('users').document(user_id)
        if users_ref.get().exists:
            return error_response("Email already registered", status=409)
        
        # Parse is_guardian
        is_guardian_raw = data.get('is_guardian', False)
        if isinstance(is_guardian_raw, str):
            is_guardian = is_guardian_raw.lower() == 'true'
        else:
            is_guardian = bool(is_guardian_raw)
        
        new_user = {
            "name": data.get('name'),
            "email": email,
            "password": data.get('password'),  # TODO: Hash with bcrypt in production
            "user_id": user_id,
            "is_guardian": is_guardian,
            "patients": [],
            "guardians": [],
            "created_at": datetime.utcnow().isoformat()
        }
        
        users_ref.set(new_user)
        
        return success_response(
            data={"user_id": user_id, "email": email},
            message="Account created successfully",
            status=201
        )
    
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    """Login user and return Bearer token."""
    try:
        data = request.get_json()
        if not data:
            data = request.form
        
        email = data.get('email', '').strip()
        password = data.get('password')
        
        if not email or not password:
            return error_response("Email and password are required", status=400)
        
        # Query user
        user_query = db.collection('users').where('email', '==', email).where('password', '==', password).stream()
        user_doc = next(user_query, None)
        
        if not user_doc:
            return error_response("Invalid credentials", status=401)
        
        user_id = user_doc.id
        user_data = user_doc.to_dict()
        
        # Create Bearer token
        access_token = create_access_token(identity=user_id)
        
        return success_response(
            data={
                "user_id": user_id,
                "email": email,
                "is_guardian": user_data.get('is_guardian', False),
                "access_token": access_token,
                "token_type": "Bearer"
            },
            message="Login successful",
            status=200
        )
    
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/auth/logout', methods=['POST', 'GET'])
@validate_user_id
def api_logout():
    """Logout by invalidating JWT token with user ID validation."""
    try:
        current_user_id = get_validated_user_id()
        return success_response(
            data={"user_id": current_user_id},
            message="Logout successful",
            status=200
        )
    except ValueError as e:
        return error_response(str(e), status=403)


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def api_get_profile():
    """Get current user profile."""
    try:
        jwt_identity = get_jwt_identity()
        header_user_id = request.headers.get('X-User-Id')
        
        if not header_user_id or header_user_id != jwt_identity:
            return error_response("X-User-Id header mismatch", status=403)
        
        user_doc = db.collection('users').document(jwt_identity).get()
        if not user_doc.exists:
            return error_response("User not found", status=404)
        
        user_data = user_doc.to_dict()
        user_data.pop('password', None)  # Never return password
        
        return success_response(data=user_data, status=200)
    
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


# ==========================================
# MEDICATIONS API
# ==========================================

@app.route('/api/medications', methods=['GET'])
@validate_user_id
def api_get_medications():
    """Get medications for user or their patients (if guardian)."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        
        if not user_doc.exists:
            return error_response("User not found", status=404)
        
        user_data = user_doc.to_dict()
        is_guardian = user_data.get('is_guardian', False)
        allowed_patients = user_data.get('patients', []) if is_guardian else []
        
        # Get target user (either self or queried patient)
        target_id = request.args.get('patient_id')
        
        if target_id:
            if target_id != current_user_id and target_id not in allowed_patients:
                return error_response("Permission denied: Cannot access this patient's medications", status=403)
        else:
            target_id = current_user_id
        
        # Fetch medications
        medications = []
        meds_snapshot = db.collection('medications').where('user_id', '==', target_id).stream()
        
        for med in meds_snapshot:
            med_data = med.to_dict()
            med_id = med.id
            med_data['id'] = med_id
            
            # Fetch reminders for this medication
            reminders_ref = db.collection('reminders').where('medication_id', '==', med_id).stream()
            med_data['reminders'] = [
                {"id": r.id, **r.to_dict()} for r in reminders_ref
            ]
            medications.append(med_data)
        
        # Sort by start_date descending
        medications = sorted(medications, key=lambda x: x.get('start_date', ''), reverse=True)
        
        return success_response(
            data={
                "target_user_id": target_id,
                "medications": medications
            },
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/medications/add', methods=['POST'])
@validate_user_id
def api_add_medicine():
    """Add new medication with reminders."""
    try:
        current_user_id = get_validated_user_id()
        data = request.get_json()
        if not data:
            data = request.form
        
        # Validate required fields
        if not data.get('name') or not data.get('dosage'):
            return error_response("Missing required fields: name, dosage", status=400)
        
        # Extract reminder times
        times = [data.get('time_1'), data.get('time_2'), data.get('time_3')]
        valid_times = [str(t).strip() for t in times if t and str(t).strip()]
        
        if not valid_times:
            return error_response("Please provide at least one reminder time", status=400)
        
        # Create medication
        med_ref = db.collection('medications').document()
        med_id = med_ref.id
        
        medication_data = {
            'user_id': current_user_id,
            'name': data.get('name'),
            'dosage': data.get('dosage'),
            'frequency': data.get('frequency', 'as needed'),
            'instructions': data.get('instructions', ''),
            'start_date': data.get('start_date'),
            'end_date': data.get('end_date'),
            'created_at': datetime.utcnow().isoformat()
        }
        
        med_ref.set(medication_data)
        
        # Create reminders
        reminders = []
        for time_str in valid_times:
            reminder_doc = db.collection('reminders').document()
            reminder_data = {
                'medication_id': med_id,
                'user_id': current_user_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            reminder_doc.set(reminder_data)
            reminders.append({"id": reminder_doc.id, **reminder_data})
        
        return success_response(
            data={
                "medication": {"id": med_id, **medication_data},
                "reminders": reminders
            },
            message="Medication added successfully",
            status=201
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Failed to add medication: {str(e)}", status=500)


@app.route('/api/medications/<string:medication_id>', methods=['GET'])
@validate_user_id
def api_get_medicine_detail(medication_id):
    """Get medication details with reminders."""
    try:
        current_user_id = get_validated_user_id()
        
        med_ref = db.collection('medications').document(medication_id)
        med = med_ref.get()
        
        if not med.exists:
            return error_response("Medication not found", status=404)
        
        med_data = med.to_dict()
        med_owner = med_data.get('user_id')
        
        # Check access control
        user_doc = db.collection('users').document(current_user_id).get()
        is_guardian = user_doc.to_dict().get('is_guardian', False)
        allowed_patients = user_doc.to_dict().get('patients', []) if is_guardian else []
        
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return error_response("Permission denied: Cannot access this medication", status=403)
        
        med_data['id'] = med.id
        
        # Fetch reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        med_data['reminders'] = [{"id": r.id, **r.to_dict()} for r in reminders_ref]
        
        return success_response(data=med_data, status=200)
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/medications/<string:medication_id>', methods=['PUT', 'POST'])
@validate_user_id
def api_edit_medication(medication_id):
    """Update medication details."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        is_guardian = user_doc.to_dict().get('is_guardian', False)
        allowed_patients = user_doc.to_dict().get('patients', []) if is_guardian else []
        
        data = request.get_json()
        if not data:
            data = request.form
        
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            return error_response("Medication not found", status=404)
        
        med_owner = med_doc.to_dict().get('user_id')
        
        # Access control
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return error_response("Permission denied: Cannot modify this medication", status=403)
        
        old_data = med_doc.to_dict()
        
        # Update fields
        updates = {
            'name': data.get('name', old_data.get('name')),
            'dosage': data.get('dosage', old_data.get('dosage')),
            'frequency': data.get('frequency', old_data.get('frequency')),
            'instructions': data.get('instructions', old_data.get('instructions')),
            'start_date': data.get('start_date', old_data.get('start_date')),
            'end_date': data.get('end_date', old_data.get('end_date'))
        }
        
        # Remove None values
        updates = {k: v for k, v in updates.items() if v is not None}
        
        med_ref.update(updates)
        
        return success_response(
            data={"medication_id": medication_id},
            message="Medication updated successfully",
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Failed to edit medication: {str(e)}", status=500)


@app.route('/api/medications/<string:medication_id>', methods=['DELETE'])
@validate_user_id
def api_delete_medication(medication_id):
    """Delete medication and associated reminders."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        is_guardian = user_doc.to_dict().get('is_guardian', False)
        allowed_patients = user_doc.to_dict().get('patients', []) if is_guardian else []
        
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            return error_response("Medication not found", status=404)
        
        med_owner = med_doc.to_dict().get('user_id')
        
        # Access control
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return error_response("Permission denied: Cannot delete this medication", status=403)
        
        # Delete medication
        med_ref.delete()
        
        # Delete reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        deleted_count = 0
        for reminder in reminders_ref:
            reminder.reference.delete()
            deleted_count += 1
        
        return success_response(
            data={
                "medication_id": medication_id,
                "reminders_deleted": deleted_count
            },
            message="Medication deleted successfully",
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Error deleting medication: {str(e)}", status=500)


@app.route('/api/reminders/<string:reminder_id>/status', methods=['POST', 'PUT'])
@validate_user_id
def api_update_reminder(reminder_id):
    """Update reminder status (taken/missed)."""
    try:
        current_user_id = get_validated_user_id()
        data = request.get_json()
        if not data:
            data = request.form
        
        status = data.get('status', '').lower()
        if status not in ['taken', 'missed']:
            return error_response("Status must be 'taken' or 'missed'", status=400)
        
        reminder_ref = db.collection('reminders').document(reminder_id)
        reminder_doc = reminder_ref.get()
        
        if not reminder_doc.exists:
            return error_response("Reminder not found", status=404)
        
        reminder_data = reminder_doc.to_dict()
        reminder_user = reminder_data.get('user_id')
        
        # Access control
        if reminder_user != current_user_id:
            return error_response("Permission denied: Cannot modify this reminder", status=403)
        
        reminder_ref.update({
            "status": status,
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return success_response(
            data={"reminder_id": reminder_id, "status": status},
            message=f"Reminder marked as {status}",
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


# ==========================================
# GUARDIAN API
# ==========================================

@app.route('/api/guardian/requests', methods=['GET'])
@validate_user_id
def api_get_guardian_requests():
    """Get guardian requests (sent if guardian, received if patient)."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        is_guardian = user_doc.to_dict().get('is_guardian', False)
        
        requests = []
        
        if is_guardian:
            # Guardian sees requests they've sent
            sent_requests = db.collection('guardian_requests').where('guardian_id', '==', current_user_id).stream()
            for req in sent_requests:
                req_data = req.to_dict()
                req_data['id'] = req.id
                requests.append(req_data)
        else:
            # Patient sees requests sent to them
            received_requests = db.collection('guardian_requests').where('patient_id', '==', current_user_id).stream()
            for req in received_requests:
                req_data = req.to_dict()
                req_data['id'] = req.id
                
                # Fetch guardian name
                g_doc = db.collection('users').document(req_data['guardian_id']).get()
                if g_doc.exists:
                    req_data['guardian_name'] = g_doc.to_dict().get('name', 'Unknown')
                
                requests.append(req_data)
        
        return success_response(
            data={
                "role": "guardian" if is_guardian else "patient",
                "requests": requests
            },
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/guardian/send_request', methods=['POST'])
@validate_user_id
def api_send_guardian_request():
    """Send guardian access request to patient."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        
        if not user_doc.to_dict().get('is_guardian', False):
            return error_response("Only guardians can send requests", status=403)
        
        data = request.get_json()
        if not data:
            data = request.form
        
        patient_email = data.get('patient_email', '').strip()
        if not patient_email:
            return error_response("Patient email is required", status=400)
        
        # Find patient
        patient_query = db.collection('users').where('email', '==', patient_email).stream()
        patient_doc = next(patient_query, None)
        
        if not patient_doc:
            return error_response("No user found with that email", status=404)
        
        patient_id = patient_doc.id
        patient_data = patient_doc.to_dict()
        
        # Validations
        if patient_data.get('is_guardian', False):
            return error_response("Target email is a guardian, not a patient", status=400)
        
        if patient_id == current_user_id:
            return error_response("Cannot send request to yourself", status=400)
        
        if patient_id in user_doc.to_dict().get('patients', []):
            return success_response(message="Already tracking this patient", status=200)
        
        # Check pending requests
        existing = db.collection('guardian_requests')\
            .where('guardian_id', '==', current_user_id)\
            .where('patient_id', '==', patient_id)\
            .where('status', '==', 'pending')\
            .stream()
        
        if next(existing, None):
            return success_response(message="Request already pending", status=200)
        
        # Create request
        req_ref = db.collection('guardian_requests').document()
        request_payload = {
            'guardian_id': current_user_id,
            'patient_id': patient_id,
            'patient_email': patient_email,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        }
        req_ref.set(request_payload)
        
        return success_response(
            data={"id": req_ref.id, **request_payload},
            message="Request sent successfully",
            status=201
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/guardian/handle_request/<string:request_id>', methods=['POST', 'PUT'])
@validate_user_id
def api_handle_request(request_id):
    """Accept or reject guardian request."""
    try:
        current_user_id = get_validated_user_id()
        user_doc = db.collection('users').document(current_user_id).get()
        
        if user_doc.to_dict().get('is_guardian', False):
            return error_response("Only patients can handle requests", status=403)
        
        data = request.get_json()
        if not data:
            data = request.form
        
        action = data.get('action', '').lower()
        if action not in ['accept', 'reject']:
            return error_response("Action must be 'accept' or 'reject'", status=400)
        
        request_ref = db.collection('guardian_requests').document(request_id)
        request_doc = request_ref.get()
        
        if not request_doc.exists:
            return error_response("Request not found", status=404)
        
        request_data = request_doc.to_dict()
        
        # Validations
        if request_data.get('patient_id') != current_user_id:
            return error_response("This request is not directed to you", status=403)
        
        if request_data.get('status') != 'pending':
            return error_response("Request already processed", status=400)
        
        if action == 'accept':
            guardian_id = request_data.get('guardian_id')
            
            # Link users
            db.collection('users').document(current_user_id).update({
                'guardians': firestore.ArrayUnion([guardian_id])
            })
            db.collection('users').document(guardian_id).update({
                'patients': firestore.ArrayUnion([current_user_id])
            })
            
            request_ref.update({
                'status': 'accepted',
                'resolved_at': datetime.utcnow().isoformat()
            })
            
            return success_response(message="Request accepted", status=200)
        
        else:  # reject
            request_ref.update({
                'status': 'rejected',
                'resolved_at': datetime.utcnow().isoformat()
            })
            
            return success_response(message="Request rejected", status=200)
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


@app.route('/api/guardian/search', methods=['GET'])
@validate_user_id
def api_search_guardians():
    """Search for guardians by email."""
    try:
        current_user_id = get_validated_user_id()
        query = request.args.get('email', '').strip()
        
        if not query or len(query) < 2:
            return error_response("Search query must be at least 2 characters", status=400)
        
        # Query guardians by email (prefix match for efficiency)
        guardians = []
        users_snapshot = db.collection('users').where('is_guardian', '==', True).stream()
        
        for user in users_snapshot:
            user_data = user.to_dict()
            email = user_data.get('email', '').lower()
            
            # Simple email prefix match
            if email.startswith(query.lower()):
                if user.id != current_user_id:  # Don't include self
                    guardians.append({
                        "user_id": user.id,
                        "name": user_data.get('name', ''),
                        "email": user_data.get('email', '')
                    })
        
        return success_response(
            data={"guardians": guardians},
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


# ==========================================
# AI PRESCRIPTION SCANNER API
# ==========================================

@app.route('/api/ai/prescription', methods=['POST'])
@validate_user_id
def api_scan_prescription():
    """
    Upload prescription for async processing.
    Returns immediately with job_id (202 Accepted).
    Results stored in ai_prescriptions collection.
    """
    try:
        current_user_id = get_validated_user_id()
        
        if 'prescription_file' not in request.files:
            return error_response("No file uploaded in 'prescription_file' field", status=400)
        
        file = request.files['prescription_file']
        if not file or file.filename == '':
            return error_response("Empty filename provided", status=400)
        
        # Validate file type (basic check)
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.pdf', '.gif'}
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            return error_response(f"File type not allowed. Allowed: {', '.join(allowed_extensions)}", status=400)
        
        # Create job ID
        job_id = str(uuid.uuid4())
        
        # Save to temp directory
        temp_dir = "temp_uploads"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        file_path = os.path.join(temp_dir, f"{job_id}_{file.filename}")
        file.save(file_path)
        
        # Store job metadata in Firestore (pending status)
        db.collection('ai_prescriptions').document(job_id).set({
            'user_id': current_user_id,
            'filename': file.filename,
            'status': 'processing',
            'created_at': datetime.utcnow().isoformat()
        })
        
        # Start background thread for processing
        thread = threading.Thread(
            target=process_prescription_background,
            args=(file_path, current_user_id, job_id),
            daemon=True
        )
        thread.start()
        
        return success_response(
            data={"job_id": job_id},
            message="Prescription upload queued for processing",
            status=202
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Error processing prescription: {str(e)}", status=500)


@app.route('/api/ai/prescription/<string:job_id>', methods=['GET'])
@validate_user_id
def api_get_prescription_result(job_id):
    """Poll for prescription processing results."""
    try:
        current_user_id = get_validated_user_id()
        
        job_doc = db.collection('ai_prescriptions').document(job_id).get()
        if not job_doc.exists:
            return error_response("Job not found", status=404)
        
        job_data = job_doc.to_dict()
        
        # Access control - only user who submitted can view
        if job_data.get('user_id') != current_user_id:
            return error_response("Permission denied", status=403)
        
        return success_response(
            data=job_data,
            status=200
        )
    
    except ValueError as e:
        return error_response(str(e), status=403)
    except Exception as e:
        return error_response(f"Internal server error: {str(e)}", status=500)


# ==========================================
# BACKWARD COMPATIBILITY ALIASES
# ==========================================

@app.route('/api/add_medicine', methods=['POST'])
@validate_user_id
def api_add_medicine_alias():
    """Alias for /api/medications/add (backward compatibility)."""
    return api_add_medicine()


@app.route('/api/delete_medication/<string:medication_id>', methods=['DELETE', 'POST'])
@validate_user_id
def api_delete_medication_alias(medication_id):
    """Alias for DELETE /api/medications/<id> (backward compatibility)."""
    return api_delete_medication(medication_id)


@app.route('/api/update_reminder/<string:reminder_id>', methods=['POST', 'PUT'])
@validate_user_id
def api_update_reminder_alias(reminder_id):
    """Alias for PATCH /api/reminders/<id>/status (backward compatibility)."""
    return api_update_reminder(reminder_id)


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return success_response(
        data={"status": "healthy"},
        status=200
    )


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(error):
    return error_response("Endpoint not found", status=404)


@app.errorhandler(405)
def method_not_allowed(error):
    return error_response("Method not allowed", status=405)


@app.errorhandler(500)
def internal_error(error):
    return error_response("Internal server error", status=500)


# ==========================================
# JWT ERROR HANDLERS
# ==========================================

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return error_response("Token has expired", status=401)


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return error_response("Invalid token", status=401)


@jwt.unauthorized_loader
def missing_token_callback(error):
    return error_response("Missing Authorization header or invalid token", status=401)


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == '__main__':
    # Development only
    app.run(debug=True, port=3001)
