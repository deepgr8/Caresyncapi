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

# CORS setup - allowing common local dev ports and production domain
CORS(app, supports_credentials=True, origins=[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://api.caresyncs.tech",
    "https://caresyncs.tech",
    "https://www.caresyncs.tech"
])

# Use memory for rate limiting (can be swapped for Redis if deployed full scale)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# JWT configuration
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True  # Enforce HTTPS for cookies
app.config['JWT_COOKIE_SAMESITE'] = 'None'  # Needs None for cross-origin API calls with credentials
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Disable CSRF token requirement for pure API usage

# Initialize Firebase
firebase_creds_env = os.getenv('FIREBASE_CREDENTIALS')
if firebase_creds_env:
    try:
        cred_dict = json.loads(firebase_creds_env)
        cred = credentials.Certificate(cred_dict)
    except Exception as e:
        print("Error parsing FIREBASE_CREDENTIALS env var in api.py:", e)
        cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-533d6deeae.json")
else:
    cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-533d6deeae.json")

# Prevent re-initialization if already initialized in another process/thread context
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
db = firestore.client()

# ==========================================
# AUTHENTICATION API
# ==========================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def api_register():
    data = request.get_json()
    if not data:
        # Fallback to form data for Postman compatibility if users send x-www-form-urlencoded
        data = request.form
        
    required_fields = ['name', 'email', 'password', 'confirm_password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    if data.get('password') != data.get('confirm_password'):
        return jsonify({"error": "Passwords do not match"}), 400
        
    email = data.get('email', '')
    user_id = email.split('@')[0]
    
    users_ref = db.collection('users').document(user_id)
    if users_ref.get().exists:
        return jsonify({"error": "Email already registered"}), 409

    try:
        # Parse is_guardian correctly whether it's boolean or string
        is_guardian_raw = data.get('is_guardian', False)
        if isinstance(is_guardian_raw, str):
            is_guardian = is_guardian_raw.lower() == 'true'
        else:
            is_guardian = bool(is_guardian_raw)

        new_user = {
            "name": data.get('name'),
            "email": email,
            "password": data.get('password'),
            "user_id": user_id,
            "is_guardian": is_guardian,
            "patients": [],
            "guardians": [],
            "created_at": datetime.utcnow().isoformat()
        }
        
        users_ref.set(new_user)
        return jsonify({"message": "Account created successfully", "user_id": user_id}), 201
    
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    data = request.get_json()
    if not data:
        data = request.form
        
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    users_ref = db.collection('users')
    user_query = users_ref.where('email', '==', email).where('password', '==', password).stream()
    user = next(user_query, None)
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
        
    access_token = create_access_token(identity=user.id)
    
    response = jsonify({
        "message": "Login successful", 
        "user_id": user.id,
        "is_guardian": user.to_dict().get('is_guardian', False)
    })
    set_access_cookies(response, access_token)
    return response, 200


@app.route('/api/auth/logout', methods=['POST', 'GET'])
def api_logout():
    response = jsonify({"message": "Logout successful"})
    unset_jwt_cookies(response)
    return response, 200


# ==========================================
# MEDICATIONS API
# ==========================================

@app.route('/api/medications', methods=['GET'])
@jwt_required()
def api_get_medications():
    current_user_id = get_jwt_identity()
    user_doc_ref = db.collection('users').document(current_user_id)
    user_doc = user_doc_ref.get().to_dict()
    
    if not user_doc:
        return jsonify({"error": "User profile not found"}), 404
        
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = user_doc.get('patients', []) if is_guardian else []
    
    target_id = request.args.get('patient_id')
    
    if target_id:
        if target_id != current_user_id and target_id not in allowed_patients:
            return jsonify({"error": "You do not have permission to view this patient's medications."}), 403
    else:
        target_id = current_user_id
        
    medications = []
    meds_snapshot = db.collection('medications').where('user_id', '==', target_id).stream()
    
    for med in meds_snapshot:
        med_data = med.to_dict()
        med_id = med.id
        med_data['id'] = med_id
        
        # Fetch reminders for this specific medication
        reminders_ref = db.collection('reminders').where('medication_id', '==', med_id).stream()
        med_data['schedule'] = [reminder.to_dict() for reminder in reminders_ref]
        medications.append(med_data)
        
    # Sort chronologically by start date
    medications = sorted(medications, key=lambda x: x.get('start_date', ''), reverse=True)
    
    return jsonify({
        "target_user_id": target_id,
        "medications": medications
    }), 200


@app.route('/api/medications/add', methods=['POST'])
@jwt_required()
def api_add_medicine():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    if not data:
        data = request.form
        
    try:
        times = [data.get('time_1'), data.get('time_2'), data.get('time_3')]
        valid_times = []
        for t in times:
            if t and str(t).strip():
                valid_times.append(str(t).strip())
                
        if not valid_times:
            return jsonify({"error": "Please provide at least one valid time (e.g., time_1)"}), 400
            
        med_ref = db.collection('medications').document()
        med_id = med_ref.id
        
        medication_data = {
            'user_id': current_user_id,
            'name': data.get('name'),
            'dosage': data.get('dosage'),
            'frequency': data.get('frequency'),
            'instructions': data.get('instructions', ''),
            'start_date': data.get('start_date'),
            'end_date': data.get('end_date'),
            'created_at': datetime.utcnow().isoformat()
        }
        
        med_ref.set(medication_data)
        
        reminders = []
        for time_str in valid_times:
            reminder_doc = db.collection('reminders').document()
            reminder_data = {
                'medication_id': med_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            reminder_doc.set(reminder_data)
            reminders.append({"id": reminder_doc.id, **reminder_data})
            
        return jsonify({
            "message": "Medication added successfully",
            "medication": {"id": med_id, **medication_data},
            "reminders": reminders
        }), 201

    except Exception as e:
        return jsonify({"error": f"Failed to add medication: {str(e)}"}), 500


@app.route('/api/medications/<string:medication_id>', methods=['GET'])
@jwt_required()
def api_get_medicine_detail(medication_id):
    med_ref = db.collection('medications').document(medication_id)
    med = med_ref.get()
    
    if not med.exists:
        return jsonify({"error": "Medication not found"}), 404
        
    med_data = med.to_dict()
    med_data['id'] = med.id
    
    reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
    med_data['reminders'] = [{"id": r.id, **r.to_dict()} for r in reminders_ref]
    
    return jsonify(med_data), 200


@app.route('/api/medications/<string:medication_id>', methods=['PUT', 'POST'])
@jwt_required()
def api_edit_medication(medication_id):
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = user_doc.get('patients', []) if is_guardian else []

    data = request.get_json()
    if not data:
        data = request.form
        
    try:
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            return jsonify({"error": "Medication not found"}), 404
            
        med_owner = med_doc.to_dict().get('user_id')
        
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return jsonify({"error": "Permission denied: You do not have access to modify this medication."}), 403

        updates = {
            'name': data.get('name', med_doc.to_dict().get('name')),
            'dosage': data.get('dosage', med_doc.to_dict().get('dosage')),    
            'frequency': data.get('frequency', med_doc.to_dict().get('frequency')),
            'instructions': data.get('instructions', med_doc.to_dict().get('instructions')),
            'start_date': data.get('start_date', med_doc.to_dict().get('start_date')),
            'end_date': data.get('end_date', med_doc.to_dict().get('end_date'))
        }
        
        # Remove None values
        updates = {k: v for k, v in updates.items() if v is not None}
        
        med_ref.update(updates)
        return jsonify({"message": "Medication updated successfully", "medication_id": medication_id}), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to edit medication: {str(e)}"}), 500


@app.route('/api/medications/<string:medication_id>', methods=['DELETE'])
@jwt_required()
def api_delete_medication(medication_id):
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = user_doc.get('patients', []) if is_guardian else []

    try:
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            return jsonify({"error": "Medication not found"}), 404
            
        med_owner = med_doc.to_dict().get('user_id')
        
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return jsonify({"error": "Permission denied. You cannot delete this medication."}), 403

        med_ref.delete()
        
        # Delete associated reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        deleted_reminders_count = 0
        for reminder in reminders_ref:
            reminder.reference.delete()
            deleted_reminders_count += 1
            
        return jsonify({
            "message": "Medication deleted successfully",
            "medication_id": medication_id,
            "reminders_deleted": deleted_reminders_count
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Error deleting medication: {str(e)}"}), 500


@app.route('/api/reminders/<string:reminder_id>/status', methods=['POST', 'PUT'])
@jwt_required()
def api_update_reminder(reminder_id):
    data = request.get_json()
    if not data:
        data = request.form
        
    status = data.get('status')
    if status not in ['taken', 'missed']:
        return jsonify({"error": "Status must be 'taken' or 'missed'"}), 400
        
    reminder_ref = db.collection('reminders').document(reminder_id)
    if not reminder_ref.get().exists:
        return jsonify({"error": "Reminder not found"}), 404
        
    reminder_ref.update({"status": status})
    return jsonify({"message": f"Reminder status updated to {status}", "reminder_id": reminder_id}), 200


# ==========================================
# GUARDIAN API
# ==========================================

@app.route('/api/guardian/requests', methods=['GET'])
@jwt_required()
def api_get_guardian_requests():
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    
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
                req_data['guardian_name'] = g_doc.to_dict().get('name', 'Unknown Guardian')
                
            requests.append(req_data)
            
    return jsonify({
        "role": "guardian" if is_guardian else "patient",
        "requests": requests
    }), 200


@app.route('/api/guardian/send_request', methods=['POST'])
@jwt_required()
def api_send_guardian_request():
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    
    if not user_doc.get('is_guardian', False):
        return jsonify({"error": "Only standard guardians can request to track patients."}), 403
        
    data = request.get_json()
    if not data:
        data = request.form
        
    patient_email = data.get('patient_email')
    if not patient_email:
        return jsonify({"error": "Patient email is required."}), 400
        
    # Find patient
    patient_query = db.collection('users').where('email', '==', patient_email).stream()
    patient_doc = next(patient_query, None)
    
    if not patient_doc:
        return jsonify({"error": "No patient found with that email address."}), 404
        
    patient_id = patient_doc.id
    
    if patient_doc.to_dict().get('is_guardian', False):
        return jsonify({"error": "The target email belongs to a Guardian account, not a Patient."}), 400
        
    if patient_id == current_user_id:
        return jsonify({"error": "You cannot send a tracking request to yourself."}), 400
        
    # Check existing linked patients
    if patient_id in user_doc.get('patients', []):
        return jsonify({"message": "You are already tracking this patient."}), 200
        
    # Check pending requests
    existing_requests = db.collection('guardian_requests')\
        .where('guardian_id', '==', current_user_id)\
        .where('patient_id', '==', patient_id)\
        .where('status', '==', 'pending')\
        .stream()
        
    if next(existing_requests, None):
        return jsonify({"message": "A tracking request is already pending for this patient."}), 200
        
    # Dispatch request
    req_ref = db.collection('guardian_requests').document()
    request_payload = {
        'guardian_id': current_user_id,
        'patient_id': patient_id,
        'patient_email': patient_email,
        'status': 'pending',
        'created_at': datetime.utcnow().isoformat()
    }
    req_ref.set(request_payload)
    
    return jsonify({
        "message": "Tracking request sent successfully to the patient.",
        "request": {"id": req_ref.id, **request_payload}
    }), 201


@app.route('/api/guardian/handle_request/<string:request_id>', methods=['POST', 'PUT'])
@jwt_required()
def api_handle_request(request_id):
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    
    if user_doc.get('is_guardian', False):
        return jsonify({"error": "Only patients can accept or reject requests."}), 403
        
    data = request.get_json()
    if not data:
        data = request.form
        
    action = data.get('action')
    if action not in ['accept', 'reject']:
        return jsonify({"error": "Action must be 'accept' or 'reject'"}), 400
        
    request_ref = db.collection('guardian_requests').document(request_id)
    request_doc = request_ref.get()
    
    if not request_doc.exists:
        return jsonify({"error": "Request not found."}), 404
        
    request_data = request_doc.to_dict()
    
    if request_data.get('patient_id') != current_user_id:
        return jsonify({"error": "Permission denied. This request is not directed to you."}), 403
        
    if request_data.get('status') != 'pending':
        return jsonify({"error": "This request has already been processed."}), 400
        
    if action == 'accept':
        guardian_id = request_data.get('guardian_id')
        
        # Link arrays
        db.collection('users').document(current_user_id).update({
            'guardians': firestore.ArrayUnion([guardian_id])
        })
        db.collection('users').document(guardian_id).update({
            'patients': firestore.ArrayUnion([current_user_id])
        })
        
        request_ref.update({'status': 'accepted', 'resolved_at': datetime.utcnow().isoformat()})
        return jsonify({"message": "Tracking request accepted successfully."}), 200
        
    elif action == 'reject':
        request_ref.update({'status': 'rejected', 'resolved_at': datetime.utcnow().isoformat()})
        return jsonify({"message": "Tracking request rejected."}), 200


# ==========================================
# AI SCANNER API
# ==========================================

@app.route('/api/ai/prescription', methods=['POST'])
@jwt_required()
def api_scan_prescription():
    if 'prescription_file' not in request.files:
        return jsonify({"error": "No file uploaded in the 'prescription_file' field"}), 400
        
    file = request.files['prescription_file']
    if file.filename == '':
        return jsonify({"error": "Empty filename provided"}), 400
        
    try:
        # Create temp dir
        temp_dir = "temp_uploads"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            
        file_path = os.path.join(temp_dir, file.filename)
        file.save(file_path)

        # AI processing
        extracted_data = extract_and_format_medicine_data(file_path)
        
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)

        return jsonify({
            "message": "Prescription successfully scanned",
            "extracted_data": extracted_data
        }), 200

    except Exception as e:
        return jsonify({"error": f"Error scanning prescription: {str(e)}"}), 500


if __name__ == '__main__':
    # Local fallback
    app.run(debug=True, port=3001)