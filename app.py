from flask import Flask, abort, request, jsonify,render_template,redirect,url_for,flash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    unset_jwt_cookies
)
from datetime import datetime, timedelta
import firebase_admin
import json
import re
import os
from dotenv import load_dotenv
from firebase_admin import credentials, firestore
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ais import extract_and_format_medicine_data

# Load environment variables
load_dotenv()

config = {
    "apiKey": "AIzaSyA_MMnYcdYzpDYjPYVLNNRRkjU1oSL_vyg",
    "authDomain": "caresync-25.firebaseapp.com",
    "projectId": "caresync-25",
    "storageBucket": "caresync-25.firebasestorage.app",
    "messagingSenderId": "790800722499",
    "appId": "1:790800722499:web:dd3959d7ae5a2513bb42f6",
    "measurementId": "G-EZ3SMDH9XJ"
}
app = Flask(__name__)
from flask_cors import CORS

# Allow specific origins for API subdomains and the main domain
CORS(app, supports_credentials=True, origins=[
    "http://localhost:3000", 
    "http://127.0.0.1:3000", 
    "https://caresyncs.tech", 
    "https://www.caresyncs.tech", 
    "https://api.caresyncs.tech"
])

# Initialize Security Headers (Talisman)
csp = {
    'default-src': [
        '\'self\'',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://cdn.jsdelivr.net'
    ],
    'img-src': ['*', 'data:'],
    'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdn.jsdelivr.net'],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://fonts.googleapis.com'],
}
Talisman(app, content_security_policy=csp)

# Initialize Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-dev-key')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-dev-key')

# Initialize extensions
jwt = JWTManager(app)

# JWT configuration
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True  # Enforce HTTPS for cookies
app.config['JWT_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Handled by SameSite=Lax for now

# Initialize Firebase
firebase_creds_env = os.getenv('FIREBASE_CREDENTIALS')
if firebase_creds_env:
    # Use environment variable for production (Vercel)
    cred_dict = json.loads(firebase_creds_env)
    cred = credentials.Certificate(cred_dict)
else:
    # Fallback to local file for development
    cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-533d6deeae.json")

firebase_admin.initialize_app(cred)
db = firestore.client()
guardian_patients_ref = db.collection('guardian_patients')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('index'))
    unset_jwt_cookies(response)
    return response
# Auth Endpoints
@app.route('/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    # Read from form data instead of JSON
    data = request.form
    
    if data.get('password') != data.get('confirm_password'):
        flash("Passwords do not match", "error")
        return redirect(url_for('register_page'))
        
    user_id = data.get('email', '').split('@')[0]
    users_ref = db.collection('users').document(user_id)
    existing = users_ref.get()
    if existing.exists:
        flash("Email already registered", "error")
        return redirect(url_for('register_page'))

    print(data)

    try:
        new_user = {
            "name": data.get('name'),
            "email": data.get('email'),
            "password": data.get('password'),
            "user_id":user_id,
            "is_guardian": data.get('is_guardian') == 'true',
            "patients": [],
            "guardians": [],
            "created_at": datetime.utcnow().isoformat()
        }
        
        users_ref.set(new_user)
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for('index'))
    
    except Exception as e:
        print(e)   
        flash("Error creating account", "error")
        return redirect(url_for('register_page'))



from flask_jwt_extended import set_access_cookies

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Read from form data instead of JSON
    email = request.form.get('email')
    password = request.form.get('password')
    
    users_ref = db.collection('users')
    user_query = users_ref.where('email', '==', email).where('password', '==', password).stream()
    user = next(user_query, None)
    
    if not user:
        flash("Invalid credentials", "error")
        return redirect(url_for('index'))
        
    access_token = create_access_token(identity=user.id)
    response = redirect(url_for('dashboard'))
    set_access_cookies(response, access_token)
    
    return response

# Custom Jinja filter for date formatting
def datetimeformat(value, format="%Y-%m-%d %H:%M:%S"):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value  # Return as is if not a datetime object

app.jinja_env.filters['datetimeformat'] = datetimeformat  # Register the filter

# Context processor to inject common variables into all templates
@app.context_processor
def inject_user():
    user_name = None
    try:
        from flask_jwt_extended import verify_jwt_in_request
        verify_jwt_in_request(optional=True)
        current_user = get_jwt_identity()
        if current_user:
            user_doc = db.collection('users').document(current_user).get()
            if user_doc.exists:
                user_name = user_doc.to_dict().get('name')
    except:
        pass
    
    return dict(
        current_user_name=user_name,
        today_date=datetime.now().strftime("%A, %B %d, %Y"),
        today_date_iso=datetime.now().strftime("%Y-%m-%d")
    )

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    medications = []
    
    meds = db.collection('medications').where('user_id', '==', current_user).stream()
    stats = {'total': 0, 'taken': 0, 'missed': 0, 'total_today': 0, 'pct': 0}
    all_reminders = []
    
    for med in meds:
        stats['total'] += 1
        med_data = med.to_dict()
        med_data['id'] = med.id
        medications.append(med_data)
        
        reminders = db.collection('reminders').where('medication_id', '==', med.id).stream()
        for r in reminders:
            r_data = r.to_dict()
            r_data['id'] = r.id
            r_data['medicine_name'] = med_data.get('name')
            r_data['dosage'] = med_data.get('dosage')
            all_reminders.append(r_data)
            
            # Simple stats based on first few reminders (assuming they are today for the demo)
            stats['total_today'] += 1
            if r_data.get('status') == 'taken':
                stats['taken'] += 1
            elif r_data.get('status') == 'missed':
                stats['missed'] += 1

    if stats['total_today'] > 0:
        stats['pct'] = round((stats['taken'] / stats['total_today']) * 100)
        
    # Sort reminders by time
    all_reminders = sorted(all_reminders, key=lambda x: x.get('time', '23:59'))

    return render_template('dashboard.html', active_page='dashboard', stats=stats, reminders=all_reminders)

@app.route('/ai/prescription', methods=['GET', 'POST'])
@jwt_required()
def process_prescription():
    if request.method == 'GET':
        return render_template('ai_upload.html', active_page='ai')
        
    print("Processing prescription")
    current_user = get_jwt_identity()
    if 'image' not in request.files:
        flash("No image provided", "error")
        return redirect(url_for('process_prescription'))

    # Save temporary image
    image_file = request.files['image']
    temp_path = f"/tmp/{image_file.filename}"
    image_file.save(temp_path)
    extracted_medicine_data = extract_and_format_medicine_data(temp_path)
    
    # Extract and format medicine data using AI
    try:
        medications = json.loads(extracted_medicine_data)
    except Exception as e:
        flash("Failed to parse AI response. Please try again.", "error")
        return redirect(url_for('process_prescription'))

    added_count = 0

    for med in medications:
        try:
            start_date = datetime.strptime(med['start_date'], "%Y-%m-%d").date()
            end_date = datetime.strptime(med['end_date'], "%Y-%m-%d").date() if med['end_date'] else None
        except KeyError:
            continue

        start_date_str = start_date.isoformat()

        # Check if medication already exists in Firestore
        existing_med = db.collection('medications').where('name', '==', med['name']).where('start_date', '==', start_date_str).get()
        if existing_med:
            continue  # Skip adding this medication if it already exists

        # Medication Data for Firestore
        medication_data = {
            'user_id': current_user,
            'name': med.get('name', 'Unknown Medicine'),
            'dosage': med.get('dosage', ''),
            'frequency': med.get('frequency'),
            'instructions': med.get('instruction'),
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat() if end_date else None,
            'created_at': datetime.utcnow().isoformat()
        }

        # Add medication to Firestore
        med_ref = db.collection('medications').document()
        med_ref.set(medication_data)
        med_id = med_ref.id
        added_count += 1

        # Generate reminders based on frequency or predefined times
        reminder_times = []
        if med.get('frequency') == 'twice a day':
            reminder_times = ['08:00', '20:00']
        elif med.get('frequency') in ['once a day', 'once', 'once daily']:
            reminder_times = ['08:00']  
        else:
            instructions = med.get('instruction', '') 
            if instructions:
                times = re.findall(r'\b\d{1,2}:\d{2}\b', instructions)
                reminder_times = [f"{int(t.split(':')[0]):02d}:{t.split(':')[1]}" for t in times]

        # Validate and format times
        valid_times = []
        for time_str in reminder_times:
            try:
                datetime.strptime(time_str, "%H:%M")
                valid_times.append(time_str)
            except ValueError:
                continue

        # Create reminders
        for time_str in valid_times:
            reminder_data = {
                'medication_id': med_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            db.collection('reminders').document().set(reminder_data)

    if added_count > 0:
        flash(f"Successfully processed and added {added_count} medications from prescription.", "success")
    else:
        flash("Analyzed prescription, but no new medications were added.", "error")
        
    return redirect(url_for('medications'))


# Get Add Medicine page
@app.route('/add_medicine', methods=['GET'])
@jwt_required()
def add_medicine():
    return render_template('add_medicine.html', active_page='medications')

# Manual medication add process and API
@app.route('/add_medicine', methods=['POST'])
@jwt_required()
def add_manual_medication():
    try:
        current_user = get_jwt_identity()
        data = request.form
        patient_id = current_user

        # Grab explicit times
        times = [
            data.get('time_1'),
            data.get('time_2'),
            data.get('time_3')
        ]
        
        # Filter out empties and validate
        valid_times = []
        for t in times:
            if t and t.strip():
                clean_t = t.strip()
                try:
                    # Try 24-hour format
                    parsed_time = datetime.strptime(clean_t, "%H:%M").strftime("%H:%M")
                    valid_times.append(parsed_time)
                except ValueError:
                    try:
                        # Try 12-hour AM/PM format
                        parsed_time = datetime.strptime(clean_t, "%I:%M %p").strftime("%H:%M")
                        valid_times.append(parsed_time)
                    except ValueError:
                        continue

        if not valid_times:
            flash("Please provide at least one valid time.", "error")
            return redirect(url_for('add_medicine'))

        med_ref = db.collection('medications').document()
        med_id = med_ref.id

        medication_data = {
            'user_id': patient_id,
            'name': data.get('name'),
            'dosage': data.get('dosage'),
            'frequency': data.get('frequency'),
            'instructions': data.get('instructions', ''),
            'start_date': data.get('start_date'),
            'end_date': data.get('end_date'),
            'created_at': datetime.utcnow().isoformat()
        }

        med_ref.set(medication_data)

        for time_str in valid_times:
            db.collection('reminders').add({
                'medication_id': med_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            })

        flash("Medication added successfully", "success")
        return redirect(url_for('medications'))

    except Exception as e:
        flash("Error adding medicines", "error")
        return redirect(url_for('add_medicine'))
       

# Get all medications for the current user (and their patients if guardian)
@app.route('/medications', methods=['GET'])
@jwt_required()
def medications():
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = []
    
    if is_guardian:
        patient_ids = user_doc.get('patients', [])
        for pid in patient_ids:
            p_doc = db.collection('users').document(pid).get().to_dict()
            if p_doc:
                allowed_patients.append({
                    'id': pid,
                    'name': p_doc.get('name', 'Patient')
                })
                
    # Determine which target ID to fetch for
    target_id = request.args.get('patient_id')
    
    if target_id:
        # Verify access
        if target_id != current_user_id and target_id not in [p['id'] for p in allowed_patients]:
            flash("You do not have permission to view this patient's medications.", "error")
            return redirect(url_for('medications'))
    else:
        target_id = current_user_id # default to self
        
    output = []
    
    # Fetch target's name to display 'patient_name' on the medication card
    target_name = "You"
    if target_id != current_user_id:
        target_doc = db.collection('users').document(target_id).get().to_dict()
        target_name = target_doc.get('name', 'Patient') if target_doc else 'Patient'
        
    meds = db.collection('medications').where('user_id', '==', target_id).stream()
    for med in meds:
        med_data = med.to_dict()
        med_id = med.id
        med_data['id'] = med_id
        med_data['patient_name'] = target_name
        
        reminders_ref = db.collection('reminders').where('medication_id', '==', med_id).stream()
        med_data['schedule'] = [reminder.to_dict()['time'] for reminder in reminders_ref]
        output.append(med_data)
        
    # Sort output chronologically by start date if exists
    output = sorted(output, key=lambda x: x.get('start_date', ''), reverse=True)
    
    return render_template('medications.html', 
                           active_page='medications', 
                           medications=output,
                           is_guardian=is_guardian,
                           allowed_patients=allowed_patients,
                           current_target_id=target_id)


# Get specific medication details
@app.route('/medicineDetail/<string:medication_id>', methods=['GET'])
@jwt_required()
def get_medication(medication_id):
    med_ref = db.collection('medications').document(medication_id)
    med = med_ref.get()
    
    if not med.exists:
        return jsonify({"msg": "Medication not found"}), 404
        
    med_data = med.to_dict()
    
    # Get schedule times
    reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
    schedule = [reminder.to_dict()['time'] for reminder in reminders_ref]
    
    return jsonify({
        'name': med_data.get('name'),
        'dosage': med_data.get('dosage'),
        'frequency': med_data.get('frequency'),
        'instructions': med_data.get('instructions'),
        'start_date': med_data.get('start_date'),
        'end_date': med_data.get('end_date'),
        'schedule': schedule
    })

# specific reminder update Api Endpoint
@app.route('/update_reminder/<string:reminder_id>', methods=['POST'])
@jwt_required()
def update_reminder_status(reminder_id):
    data = request.form
    reminder_ref = db.collection('reminders').document(reminder_id)
    reminder = reminder_ref.get()
 
    if not reminder.exists:
        flash("Reminder not found", "error")
        return redirect(url_for('dashboard'))
    
    if data.get('status') in ['taken', 'missed']:
        reminder_ref.update({"status": data['status']})
        flash("Reminder marked as " + data['status'], "success")
    else:
        flash("Invalid status", "error")
        
    return redirect(url_for('dashboard'))

# Delete specific medicine and associated reminder
@app.route('/delete_medication/<string:medication_id>', methods=['POST'])
@jwt_required()
def delete_medication(medication_id):
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = user_doc.get('patients', []) if is_guardian else []

    try:
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            flash("Medication not found", "error")
            return redirect(url_for('medications'))
            
        med_owner = med_doc.to_dict().get('user_id')
        
        # Verify permissions: Must be owner OR guardian of the owner
        if med_owner != current_user_id and med_owner not in allowed_patients:
            flash("You do not have permission to delete this medication.", "error")
            return redirect(url_for('medications'))

        # Delete medication
        med_ref.delete()
        
        # Delete associated reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        for reminder in reminders_ref:
            reminder.reference.delete() 
        
        flash("Medication deleted successfully", "success")
    except Exception as e:
        flash(f"Error deleting medication: {str(e)}", "error")
        
    return redirect(url_for('medications'))
    
# Update specific medication details
@app.route('/medications/<string:medication_id>/edit', methods=['POST'])
@jwt_required()
def edit_medication(medication_id):
    current_user_id = get_jwt_identity()
    user_doc = db.collection('users').document(current_user_id).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    allowed_patients = user_doc.get('patients', []) if is_guardian else []

    data = request.get_json()
    
    try:
        med_ref = db.collection('medications').document(medication_id)
        med_doc = med_ref.get()
        
        if not med_doc.exists:
            return jsonify({"success": False, "error": "Medication not found"}), 404
            
        med_owner = med_doc.to_dict().get('user_id')
        
        # Verify permissions
        if med_owner != current_user_id and med_owner not in allowed_patients:
            return jsonify({"success": False, "error": "Permission denied"}), 403

        # Update medication
        med_ref.update({
            'name': data['name'],
            'dosage': data['dosage']  ,    
            "frequency": data["frequency"],
            "instructions": data["instruction"],
            "start_date": data["start_date"],
            "end_date": data["end_date"]
        })
        
        # Delete existing reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        for rem in reminders_ref:
            rem.reference.delete()
        
        # Use explicit times array from frontend if provided
        explicit_times = data.get('times', [])
        reminder_times = [t for t in explicit_times if t and t.strip()]
        
        # Fallback to defaults if no times provided
        if not reminder_times:
            if data.get('frequency') == 'twice a day':
                reminder_times = ['08:00', '20:00']
            elif data.get('frequency') in ['once a day', 'once', 'once daily']: 
                reminder_times = ['08:00']  # Default morning

        # Validate and format times
        valid_times = []
        for time_str in reminder_times:
            if time_str and time_str.strip():
                clean_t = time_str.strip()
                try:
                    parsed_time = datetime.strptime(clean_t, "%H:%M").strftime("%H:%M")
                    valid_times.append(parsed_time)
                except ValueError:
                    try:
                        parsed_time = datetime.strptime(clean_t, "%I:%M %p").strftime("%H:%M")
                        valid_times.append(parsed_time)
                    except ValueError:
                        continue

        # Create reminders with valid times
        for time_str in valid_times:  # Skip creating this reminder if it already exists
            reminder_data = {
                'medication_id': medication_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            reminder_ref = db.collection('reminders').document()
            reminder_ref.set(reminder_data)
        return jsonify({"success": True}), 200
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/guardian_requests', methods=['GET'])
@jwt_required()
def guardian_requests():
    current_user = get_jwt_identity()
    user_doc = db.collection('users').document(current_user).get().to_dict()
    is_guardian = user_doc.get('is_guardian', False)
    
    if is_guardian:
        # If guardian, fetch requests THEY sent that are still pending
        requests_ref = db.collection('guardian_requests').where('guardian_id', '==', current_user).where('status', '==', 'pending').stream()
    else:
        # If patient, fetch requests sent TO them
        requests_ref = db.collection('guardian_requests').where('patient_id', '==', current_user).where('status', '==', 'pending').stream()
        
    reqs = [{'id': r.id, **r.to_dict()} for r in requests_ref]
    return render_template('guardian_requests.html', active_page='guardian', requests=reqs, is_guardian=is_guardian)

@app.route('/send_guardian_request', methods=['POST'])
@jwt_required()
def send_guardian_request():
    current_user = get_jwt_identity()
    patient_email = request.form.get('patient_email')
    
    # 1. Look up patient by email
    patient_query = db.collection('users').where('email', '==', patient_email).limit(1).stream()
    patient_doc = next(patient_query, None)
    
    if not patient_doc:
        flash("No patient found with that email address.", "error")
        return redirect(url_for('guardian_requests'))
        
    patient_id = patient_doc.id
    
    if patient_id == current_user:
        flash("You cannot send a request to yourself.", "error")
        return redirect(url_for('guardian_requests'))
        
    # Check if a pending request already exists
    existing = db.collection('guardian_requests').where('guardian_id', '==', current_user).where('patient_id', '==', patient_id).where('status', '==', 'pending').stream()
    if next(existing, None):
        flash("A pending request already exists for this patient.", "error")
        return redirect(url_for('guardian_requests'))
    
    # Get guardian name
    guardian_doc = db.collection('users').document(current_user).get().to_dict()
    guardian_name = guardian_doc.get('name', 'Someone')
        
    # Create request
    db.collection('guardian_requests').add({
        'guardian_id': current_user,
        'guardian_name': guardian_name,
        'patient_id': patient_id,
        'status': 'pending',
        'message': f"{guardian_name} would like to monitor your medication schedule.",
        'created_at': datetime.utcnow().isoformat()
    })
    
    flash("Guardian request sent successfully!", "success")
    return redirect(url_for('guardian_requests'))

# Aceepting request of the guardian
@app.route('/handle_request/<request_id>', methods=['POST'])
@jwt_required()
def handle_request(request_id):
    current_user = get_jwt_identity()
    action = request.form.get('action')
    
    request_ref = db.collection('guardian_requests').document(request_id)
    req_doc = request_ref.get()
    
    if not req_doc.exists:
        abort(404)
        
    req_data = req_doc.to_dict()
    
    if req_data['patient_id'] != current_user:
        abort(403)
    
    # Update request status
    request_ref.update({'status': action + 'ed'})
    
    if action == 'accept':
        # Update guardian's patients
        db.collection('users').document(req_data['guardian_id']).update({
            'patients': firestore.ArrayUnion([current_user])
        })
        
        # Update patient's guardians
        db.collection('users').document(current_user).update({
            'guardians': firestore.ArrayUnion([req_data['guardian_id']])
        })
    
    flash(f"Request {action}ed successfully", "success")
    return redirect(url_for('guardian_requests'))



@app.route('/ai_upload')
@jwt_required()
def ai_upload():
    return render_template('ai_upload.html', active_page='ai')
    
if __name__ == '__main__':
    app.run(debug=True)