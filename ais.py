import google.generativeai as genai
from datetime import datetime, timedelta
import json
import re



def extract_and_format_medicine_data(image_path):
    genai.configure(api_key="AIzaSyAnH0L0wjUMOfzTovn7aS5xvxxezVTDj3U")
    
    myfile = genai.upload_file(image_path)

    start_date = datetime.today().strftime("%Y-%m-%d")

    # Step 1: Extract Medicine Details from Image
    model = genai.GenerativeModel("gemini-3-flash-preview")
    result = model.generate_content(
        [myfile, "\n\n", "Extract the medicine name and thier dosage mention in the picture as a list and do this correct because it part of healthcare so no mistaken should be considered"]
    )

    # Step 2: Format Extracted Data into JSON
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

# Test Run
# extract_and_format_medicine_data("/Users/deepuprajapati/Documents/Deepu_Python_projects/CaresyncAPI/WhatsApp Image 2025-01-29 at 3.36.00 PM.jpeg")