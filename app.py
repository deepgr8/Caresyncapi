from flask import Flask, abort, request, jsonify,render_template,redirect,url_for,flash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    unset_jwt_cookies
)
from datetime import datetime
import firebase_admin
import json
from firebase_admin import credentials, firestore

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

# Configuration
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change in production
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Required for CSRF

# Initialize extensions
jwt = JWTManager(app)

# JWT configuration
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_COOKIE_SECURE'] = False  # True in production

# Initialize Firebase
cred = credentials.Certificate("caresync-25-firebase-adminsdk-fbsvc-446ed91b3c.json")  # Update with your actual Firebase credentials
firebase_admin.initialize_app(cred)
db = firestore.client()
guardian_patients_ref = db.collection('guardian_patients')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('login_page'))
    unset_jwt_cookies(response)
    return response
# Auth Endpoints
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    print(f"Registration data - is_guardian: {data.get('is_guardian')}")

    if data['password'] != data['confirm_password']:
        return {'error': 'Passwords do not match'}, 400
    user_id = data['email'].split('@')[0]
    users_ref = db.collection('users').document(user_id)
    existing = users_ref.get()
    if existing.exists:
            return {'message': 'User ID already exists'}, 400

    try:
        new_user = {
            "name": data['name'],
            "email": data['email'],
            "password": data['password'],
            "user_id":user_id,  # Remember to hash in production
            "is_guardian": data.get('is_guardian', 'false') == 'true',
            "patients": [],
            "guardians": [],
            "is_guardian": data.get('is_guardian', 'false').lower() == 'true',
            "created_at": datetime.utcnow().isoformat()
        }
        
        users_ref.set(new_user)
        return {'message': 'Account created successfully'}, 200
    
    except Exception as e:
        print(e)   
        return {'error': 'Error creating account'}, 500



@app.route('/auth/login', methods=['POST'])
def login():
    email = request.get_json().get('email')
    password = request.get_json().get('password')
    
    users_ref = db.collection('users')
    user_query = users_ref.where('email', '==', email).where('password', '==', password).stream()
    user = next(user_query, None)
    
    if not user:
        return {'error': 'Invalid credentials'}, 401
        
    access_token = create_access_token(identity=user.id)
    response = jsonify({'message': 'Login successful', 'access_token': access_token})
    
    return response











# Custom Jinja filter for date formatting
def datetimeformat(value, format="%Y-%m-%d %H:%M:%S"):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value  # Return as is if not a datetime object

app.jinja_env.filters['datetimeformat'] = datetimeformat  # Register the filter

@app.route('/dashboard')
@jwt_required()
def dashboard(user_id):
    access_token = create_access_token(identity=user_id)
    current_user = get_jwt_identity()
    # Get medications for selected patient
    medications = []
    

    meds = db.collection('medications').where('user_id', '==', current_user).stream()
    for med in meds:
            med_data = med.to_dict()
            med_data['id'] = med.id
            reminders = db.collection('reminders').where('medication_id', '==', med.id).stream()
            med_data['schedule'] = [{'id': r.id, **r.to_dict()} for r in reminders]
            medications.append(med_data)
    
    return jsonify(medications,access_token), 200

@app.route('/ai/prescription', methods=['POST'])
@jwt_required()
def process_prescription():
    print("Processing prescription")
    current_user = get_jwt_identity()
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    # Save temporary image
    image_file = request.files['image']
    temp_path = f"/tmp/{image_file.filename}"
    image_file.save(temp_path)
    extracted_medicine_data = extract_and_format_medicine_data(temp_path)
    # Extract and format medicine data using AI
    try:
        medications = json.loads(extracted_medicine_data)
    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse AI response"}), 500

    added_medications = []
    reminders_created = []

    for med in medications:
        try:
            start_date = datetime.strptime(med['start_date'], "%Y-%m-%d").date()
            end_date = datetime.strptime(med['end_date'], "%Y-%m-%d").date() if med['end_date'] else None
        except KeyError:
            return jsonify({"error": "Invalid date format from AI"}), 400

        # Check if medication already exists in Firestore
        start_date_str = start_date.isoformat()

        # Check if medication already exists in Firestore
        existing_med = db.collection('medications').where('name', '==', med['name']).where('start_date', '==', start_date_str).get()
        if existing_med:
            continue  # Skip adding this medication if it already exists

        # Medication Data for Firestore
        medication_data = {
            'user_id': current_user,
            'name': med['name'],
            'dosage': med['dosage'],
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

        # Generate reminders based on frequency or predefined times
        reminder_times = []
        import re
        if med.get('frequency') == 'twice a day':
            reminder_times = ['08:00', '20:00']
        elif med.get('frequency') in ['once a day', 'once']:  # Handle 'once'
            reminder_times = ['08:00']  # Default morning
        else:
            # Parse custom times from instruction
            instructions = med.get('instruction', '')  # Fixed key from 'instruction' to 'instructions'
    
            if instructions:  # Ensure instructions is not None
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

        # Create reminders with valid times
        for time_str in valid_times:  # Skip creating this reminder if it already exists
            reminder_data = {
                'medication_id': med_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            reminder_ref = db.collection('reminders').document()
            reminder_ref.set(reminder_data)
            reminders_created.append({
                'id': reminder_ref.id,
                'medication_id': med_id,
                'time': time_str
            })

        added_medications.append({
            'id': med_id,
            **medication_data
        })

    return jsonify({
        'message': 'Prescription processed successfully',
        'medications_added': added_medications,
        'reminders_created': reminders_created
    }), 201


import re
# Manual medication add process and API
@app.route('/Manualmedications', methods=['POST'])
@jwt_required()
def add_manual_medication():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()

        # Determine patient ID
 
        patient_id = current_user

        # Convert schedule times to list and validate
        schedule_times = [t.strip() for t in data.get('instructions', '').split(',') if t.strip()]
        valid_times = []
        for t in schedule_times:
            try:
                # Try parsing as HH:MM
                datetime.strptime(t, "%H:%M")
                valid_times.append(t)
            except ValueError:
                # Handle other formats like "8h" or "14:30"
                match = re.match(r"(\d{1,2})[h:]?(\d{0,2})", t)
                if match:
                    hour = match.group(1).zfill(2)
                    minute = match.group(2).ljust(2, '0') if match.group(2) else '00'
                    valid_time = f"{hour}:{minute}"
                    datetime.strptime(valid_time, "%H:%M")  # Validate
                    valid_times.append(valid_time)
                else:
                    continue  # Skip invalid entries

        if not valid_times:
            return{'error':'Invalid time format. Use HH:MM (e.g., 08:00 or 20:30)'}

        # Create medication document first
        med_ref = db.collection('medications').document()
        med_id = med_ref.id

        medication_data = {
            'user_id': patient_id,
            'name': data['name'],
            'dosage': data['dosage'],
            'frequency': data['frequency'],
            'instructions': data.get('instructions', ''),
            'start_date': data['start_date'],
            'end_date': data.get('end_date'),
            'created_at': datetime.utcnow().isoformat()
        }

        med_ref.set(medication_data)

        # Add reminders using the obtained med_id
        for time_str in valid_times:
            db.collection('reminders').add({
                'medication_id': med_id,
                'time': time_str,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            })

        return jsonify({"success": True, "message": "Medication added successfully"}), 200

    except Exception as e:
       return jsonify({"success": False, "message":"Error adding medicines"}), 500
       

# Get all medications for the current user
@app.route('/getmedications', methods=['GET'])
@jwt_required()
def get_medications():
    current_user = get_jwt_identity()
    medications_ref = db.collection('medications')
    meds = medications_ref.where('user_id', '==', current_user).stream()
    
    output = []
    for med in meds:
        med_data = med.to_dict()
        med_id = med.id
        reminders_ref = db.collection('reminders').where('medication_id', '==', med_id).stream()
        med_data['schedule'] = [reminder.to_dict()['time'] for reminder in reminders_ref]
        output.append(med_data)
    
    return jsonify(output), 200


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
@app.route('/updateReminders/<string:reminder_id>', methods=['PUT'])
@jwt_required()
def update_reminder_status(reminder_id):
    data = request.get_json()
    reminder_ref = db.collection('reminders').document(reminder_id)
    reminder = reminder_ref.get()
 
    if not reminder.exists:
        return jsonify({"error": "Reminder not found"}), 404
    
    if data['status'] in ['taken', 'missed']:
        reminder_ref.update({"status": data['status']})
        return jsonify(message='Status updated'), 200
    return jsonify({'error':'Invalid status'}), 400

# Delete specific medicine and associated reminder
@app.route('/delete-medications/<string:medication_id>', methods=['DELETE'])
@jwt_required()
def delete_medication(medication_id):
    try:
        # Delete medication
        db.collection('medications').document(medication_id).delete()
        
        # Delete associated reminders
        reminders_ref = db.collection('reminders').where('medication_id', '==', medication_id).stream()
        for reminder in reminders_ref:
            reminder.reference.delete()  # Delete the entire reminder document
        
            
        return jsonify({"success": True, "message": "Medication deleted successfully"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
# Update specific medication details
@app.route('/medications/<string:medication_id>/edit', methods=['POST'])
@jwt_required()
def edit_medication(medication_id):
    data = request.get_json()
    
    try:
        # Update medication
        med_ref = db.collection('medications').document(medication_id)
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
        
        # Create new reminders
        if data.get('frequency') == 'twice a day':
            reminder_times = ['08:00', '20:00']
        elif data.get('frequency') in ['once a day', 'once']:  # Handle 'once'
            reminder_times = ['08:00']  # Default morning
        else:
            # Parse custom times from instruction
            instructions = data.get('instruction', '')  # Fixed key from 'instruction' to 'instructions'
    
            if instructions:  # Ensure instructions is not None
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

# Aceepting request of the guardian
@app.route('/handle-request/<request_id>', methods=['POST'])
@jwt_required()
def handle_request(request_id):
    current_user = get_jwt_identity()
    action = request.get_json().get('action')
    
    request_ref = db.collection('guardian_requests').document(request_id)
    req_data = request_ref.get().to_dict()
    
    if not req_data or req_data['patient_id'] != current_user:
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
    
    return jsonify({"message":f'Request {action}ed successfully'}),200

import google.generativeai as genai
from datetime import datetime, timedelta
import json
import re

import datetime



def extract_and_format_medicine_data(image_path):
    genai.configure(api_key="AIzaSyATW9PLC3Ozk5oqcZh4o51oIvvbPlTWrWI")
    
    myfile = genai.upload_file(image_path)

    start_date =datetime.date.today()

    # Step 1: Extract Medicine Details from Image
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
    result = model.generate_content(
        [myfile, "\n\n", "Extract the medicine name and thier dosage mention in the picture as a list and do this correct because it part of healthcare so no mistaken should be considered"]
    )

    # Step 2: Format Extracted Data into JSON
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(
    result.text + " " + 
    "Provide the response strictly in valid JSON format only. The JSON array should contain objects with fields: "
    "'name', 'dosage', 'frequency', 'instruction', 'start_date', 'end_date'. "
    "Include specific times in 24-hour format (HH:MM) for reminders in the 'instruction' field. this field should not to be null "
    "Example: '08:00, 20:00' for twice daily. Use only actual clock times, not relative terms like 'before breakfast'."
)

    # Step 3: Clean and Parse JSON
    try:
        response_text = response.text.strip()
        response_text = re.sub(r'```json|```', '', response_text).strip()  # Remove Markdown formatting
        medicine_data = json.loads(response_text)
    except json.JSONDecodeError:
        print("Error parsing JSON. Raw AI response:", response_text)
        return {"error": "Failed to parse AI response as JSON"}

    # Step 4: Assign Start and End Dates
    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")

    for med in medicine_data:
        if "duration" in med:
            med["end_date"] = (start_date_obj + timedelta(days=med["duration"])).strftime("%Y-%m-%d")
        else:
            med["end_date"] = (start_date_obj + timedelta(days=10)).strftime("%Y-%m-%d")

        med["start_date"] = start_date
    print(json.dumps(medicine_data, indent=4))
    return json.dumps(medicine_data, indent=4)


if __name__ == '__main__':
    app.run(debug=True)
