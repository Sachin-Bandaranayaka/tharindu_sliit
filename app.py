from flask import Flask, request, jsonify, render_template, send_from_directory, session
from flask_pymongo import PyMongo
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import pickle
import pandas as pd
import numpy as np
from pymongo import MongoClient
import joblib
from bson import ObjectId
from cvss_predictor import CVSSPredictor
from cvss_predictor import predictor as cvss_predictor
import sqlite3
import uuid
import traceback

# --- Helper to construct path relative to this script ---
_BASE_DIR = os.path.dirname(__file__)
def get_model_path(filename):
    return os.path.join(_BASE_DIR, 'models', filename)
# --- End helper ---

app = Flask(__name__, static_folder=None)
app.secret_key = 'unified_risk_assessment_secret_key_2024'  # Change this in production
CORS(app)

# Load insurance model
try:
    insurance_model = joblib.load(get_model_path("final_claim_fee_predictor.pkl"))
    insurance_feature_names = joblib.load(get_model_path("feature_names.pkl"))
    print("Insurance model loaded successfully")
except Exception as e:
    print(f"Error loading insurance model: {e}")
    traceback.print_exc()
    insurance_model = None
    insurance_feature_names = None

# Dummy/Fallback model creation functions
def create_dummy_expert_model():
    """Create a simple rule-based fallback for expert risk assessment"""
    class DummyExpertModel:
        def predict(self, X):
            # Simple rule-based prediction based on input features
            # Default to 'Medium' risk (index 1)
            return [1]
        
        def predict_proba(self, X):
            # Return dummy probabilities [Low, Medium, High]
            return [[0.2, 0.6, 0.2]]
    
    class DummyEncoders:
        def __init__(self):
            # Create dummy encoders with common values for each field
            self.encoders = {
                'Organization Size': self._create_dummy_encoder(['Small', 'Medium', 'Large']),
                'Sector Type': self._create_dummy_encoder(['Technology', 'Healthcare', 'Finance', 'Manufacturing', 'Education', 'Government', 'Retail']),
                'Info Sec Policy Availability': self._create_dummy_encoder(['Yes', 'No']),
                'Incident Response Plan': self._create_dummy_encoder(['Yes', 'No']),
                'Incident Plan Testing': self._create_dummy_encoder(['Never', 'Annually', 'Quarterly', 'Monthly']),
                'Physical Access Control Implementation': self._create_dummy_encoder(['Fully Implemented', 'Partially Implemented', 'Not Implemented']),
                'Remote Access Security Measures': self._create_dummy_encoder(['VPN + MFA', 'VPN', 'None']),
                'Backup and Recovery Procedures': self._create_dummy_encoder(['Regular', 'Irregular', 'None']),
                'Employee Training on Information Security': self._create_dummy_encoder(['Regular', 'Occasionally', 'Never']),
                'Data Encryption Practice': self._create_dummy_encoder(['Both', 'At Rest', 'In Transit', 'None']),
                'Antivirus Software': self._create_dummy_encoder(['Yes', 'No']),
                'Vulnerability Scanning Frequency': self._create_dummy_encoder(['Continuous', 'Monthly', 'Quarterly', 'Annually', 'Never']),
                'Risk Assessment Frequency': self._create_dummy_encoder(['Quarterly', 'Annually', 'Never']),
                'Incident Reporting Mechanism': self._create_dummy_encoder(['Formal', 'Informal', 'None']),
                'Third-party Risk Management': self._create_dummy_encoder(['Comprehensive', 'Basic', 'None']),
                'Compliance Monitoring Frequency': self._create_dummy_encoder(['Continuous', 'Monthly', 'Quarterly', 'Annually']),
                'Information Asset Inventory': self._create_dummy_encoder(['Complete', 'Partial', 'None']),
                'Business Continuity Management': self._create_dummy_encoder(['Comprehensive', 'Basic', 'None']),
                'Security Audit History': self._create_dummy_encoder(['Regular', 'Occasional', 'Never'])
            }
        
        def _create_dummy_encoder(self, classes):
            class DummyLabelEncoder:
                def __init__(self, classes):
                    self.classes_ = classes
                
                def transform(self, values):
                    return [self.classes_.index(v) if v in self.classes_ else 0 for v in values]
            
            return DummyLabelEncoder(classes)
        
        def __getitem__(self, key):
            return self.encoders.get(key, self._create_dummy_encoder(['Unknown']))
        
        def __contains__(self, key):
            return key in self.encoders
        
        def keys(self):
            return self.encoders.keys()
    
    return DummyExpertModel(), DummyEncoders()

def calculate_rule_based_risk(data):
    """Calculate risk score based on simple rules"""
    risk_score = 0
    
    # High risk factors
    high_risk_conditions = [
        data.get('info_sec_policy_availability') == 'No',
        data.get('incident_response_plan') == 'No',
        data.get('antivirus_software') == 'No',
        data.get('data_encryption_practice') == 'None',
        data.get('vulnerability_scanning_frequency') == 'Never',
        data.get('employee_training_on_information_security') == 'Never'
    ]
    
    # Medium risk factors
    medium_risk_conditions = [
        data.get('incident_plan_testing') in ['Never', 'Annually'],
        data.get('physical_access_control_implementation') == 'Partially Implemented',
        data.get('backup_and_recovery_procedures') == 'Irregular',
        data.get('risk_assessment_frequency') == 'Never'
    ]
    
    # Count risk factors
    high_risk_count = sum(high_risk_conditions)
    medium_risk_count = sum(medium_risk_conditions)
    
    # Calculate risk level
    if high_risk_count >= 3:
        return 2  # High risk
    elif high_risk_count >= 1 or medium_risk_count >= 3:
        return 1  # Medium risk
    else:
        return 0  # Low risk

# Load expert-based risk assessment models (Mohan's functionality)
expert_model_method = 'unknown'
try:
    expert_rf_model = joblib.load(get_model_path('risk_assessment_model.joblib'))
    try:
        expert_encoders = joblib.load(get_model_path('label_encoders_dict.joblib'))
        print("Expert-based risk assessment models loaded successfully")
        expert_model_method = 'ml'
    except FileNotFoundError:
        try:
            expert_encoders = joblib.load(get_model_path('risk_label_encoders_dict.joblib'))
            print("Expert risk label encoders loaded successfully")
            expert_model_method = 'ml'
        except FileNotFoundError:
            print("Warning: Expert risk label encoders not found. Using fallback model.")
            expert_rf_model, expert_encoders = create_dummy_expert_model()
            expert_model_method = 'rule-based'
except ValueError as ve:
    print(f"ERROR: Critical version incompatibility when loading risk assessment model: {ve}")
    traceback.print_exc()
    print("Using fallback rule-based model due to scikit-learn version incompatibility.")
    expert_rf_model, expert_encoders = create_dummy_expert_model()
    expert_model_method = 'rule-based'
except FileNotFoundError:
    print("Warning: Expert-based risk assessment models not found. Using fallback model.")
    expert_rf_model, expert_encoders = create_dummy_expert_model()
    expert_model_method = 'rule-based'

# Load CVSS model components
try:
    with open(get_model_path('cvss_model.pkl'), 'rb') as file:
        cvss_model = pickle.load(file)
    with open(get_model_path('tfidf_vectorizer.pkl'), 'rb') as file:
        tfidf_vectorizer = pickle.load(file)
    with open(get_model_path('onehot_encoder.pkl'), 'rb') as file:
        onehot_encoder = pickle.load(file)
    print("CVSS model components loaded successfully")
except Exception as e:
    print(f"Error loading CVSS model components: {e}")
    cvss_model = None
    tfidf_vectorizer = None
    onehot_encoder = None

# SQLite setup for user authentication
def init_sqlite_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("SQLite database initialized successfully")

# Initialize SQLite database
init_sqlite_db()

# MongoDB setup for insurance (optional)
try:
    mongo_client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    db = mongo_client["claim_fee_db"]
    collection = db["predictions"]
    # Test the connection
    mongo_client.admin.command('ping')
    print("MongoDB connected successfully")
except Exception as e:
    print(f"MongoDB connection error: {e}")
    print("Continuing without MongoDB - predictions will not be saved to database")
    mongo_client = None
    db = None
    collection = None

# Routes for serving static files
@app.route('/')
def index():
    return send_from_directory('cvss-risk-dashboard', 'home.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('cvss-risk-dashboard/static', filename)

@app.route('/<path:path>')
def serve_file(path):
    return send_from_directory('cvss-risk-dashboard', path)

# Insurance prediction routes
@app.route("/insurance")
def insurance_dashboard():
    return send_from_directory('templates', 'dashboard.html')

@app.route("/insurance/predict")
def insurance_predict_form():
    return send_from_directory('templates', 'index.html')

@app.route("/insurance/history")
def insurance_history():
    return send_from_directory('templates', 'history.html')

# API Routes

@app.route('/api/cvss/predict-simple', methods=['POST'])
def predict_cvss_simple():
    """
    Alternative CVSS prediction endpoint using the simple model.
    """
    try:
        data = request.get_json()
        if not data or not cvss_model:
            return jsonify({"error": "Model not available or no data provided"}), 400
        
        # Extract parameters
        cwe_code = data.get('cwe_code', 0)
        access_authentication = data.get('access_authentication', 'None')
        access_complexity = data.get('access_complexity', 'Low')
        access_vector = data.get('access_vector', 'Network')
        impact_availability = data.get('impact_availability', 'None')
        impact_confidentiality = data.get('impact_confidentiality', 'None')
        impact_integrity = data.get('impact_integrity', 'None')
        summary = data.get('summary', '')
        
        # Prepare input data
        input_data = {
            'cwe_code': [cwe_code],
            'access_authentication': [access_authentication],
            'access_complexity': [access_complexity],
            'access_vector': [access_vector],
            'impact_availability': [impact_availability],
            'impact_confidentiality': [impact_confidentiality],
            'impact_integrity': [impact_integrity],
        }
        
        input_df = pd.DataFrame(input_data)
        
        # One-hot encode categorical features
        encoded_features = onehot_encoder.transform(input_df[['access_authentication', 'access_complexity', 'access_vector',
                                                               'impact_availability', 'impact_confidentiality', 
                                                               'impact_integrity']])
        encoded_df = pd.DataFrame(encoded_features, columns=onehot_encoder.get_feature_names_out())
        
        # Transform summary text
        summary_features = tfidf_vectorizer.transform([summary])
        tfidf_summary_df = pd.DataFrame(summary_features.toarray(), columns=tfidf_vectorizer.get_feature_names_out())
        
        # Combine features
        input_data_combined = pd.concat([input_df[['cwe_code']], encoded_df, tfidf_summary_df], axis=1)
        
        # Make prediction
        prediction = cvss_model.predict(input_data_combined)[0]
        
        # Validate prediction result
        if prediction is None or np.isnan(prediction) or np.isinf(prediction):
            prediction = 0.0
            print(f"Warning: Invalid prediction result, defaulting to 0.0")
        
        # Ensure prediction is within valid CVSS range (0-10)
        prediction = max(0.0, min(10.0, float(prediction)))
        
        return jsonify({
            "cvss_score": float(prediction),
            "risk_level": "High" if prediction >= 7.0 else "Medium" if prediction >= 4.0 else "Low",
            "success": True
        })
        
    except Exception as e:
        print(f"CVSS Simple Prediction error: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/insurance/predict', methods=['POST'])
def predict_insurance():
    """
    API endpoint for insurance claim fee prediction.
    """
    try:
        if not insurance_model:
            return jsonify({"error": "Insurance model not available"}), 500
            
        form_data = request.get_json()
        if not form_data:
            return jsonify({"error": "No input data provided"}), 400
        
        # Preprocess the data
        processed_data = preprocess_insurance_data(form_data)
        
        # Make prediction
        prediction = insurance_model.predict(processed_data)[0]
        
        # Save to MongoDB if available
        if collection is not None:
            prediction_record = {
                "timestamp": datetime.now(),
                "input_data": form_data,
                "predicted_claim_fee": float(prediction)
            }
            collection.insert_one(prediction_record)
        
        return jsonify({
            "predicted_claim_fee": float(prediction),
            "success": True
        })
        
    except Exception as e:
        print(f"Insurance Prediction error: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def preprocess_insurance_data(form_data):
    """
    Preprocess insurance form data for model prediction.
    """
    try:
        # Parse date
        date_of_incident = datetime.strptime(form_data["Date of Incident"], "%Y-%m-%d")
        form_data["Incident Year"] = date_of_incident.year
        form_data["Incident Month"] = date_of_incident.month
        form_data["Incident Day"] = date_of_incident.day
        
        # Create input data dictionary
        input_data = {
            "Incurred Loss Amount": [float(form_data["Incurred Loss Amount"])],
            "Requested Coverage Percentage": [float(form_data["Requested Coverage Percentage"])],
            "Deductible": [float(form_data["Deductible"])],
            "Coverage Limit": [float(form_data["Coverage Limit"])],
            "Coverage Percentage": [float(form_data["Coverage Percentage"])],
            "Verified Incurred Loss Amount": [float(form_data["Verified Incurred Loss Amount"])],
            "Loss After Deductible": [float(form_data["Loss After Deductible"])],
            "Capped Loss": [float(form_data["Capped Loss"])],
            "Incident Year": [form_data["Incident Year"]],
            "Incident Month": [form_data["Incident Month"]],
            "Incident Day": [form_data["Incident Day"]]
        }
        
        # Convert to DataFrame
        input_df = pd.DataFrame(input_data)
        
        # Ensure columns match the model's expected input
        input_df = input_df.reindex(columns=insurance_feature_names, fill_value=0)
        
        return input_df
        
    except Exception as e:
        print(f"Data preprocessing error: {str(e)}")
        raise e

@app.route('/api/insurance/history', methods=['GET'])
def get_insurance_history():
    """
    Get insurance prediction history from MongoDB.
    """
    try:
        if not collection:
            return jsonify({"error": "Database not available"}), 500
            
        # Get recent predictions
        predictions = list(collection.find().sort("timestamp", -1).limit(50))
        
        # Convert ObjectId to string for JSON serialization
        for pred in predictions:
            pred["_id"] = str(pred["_id"])
            pred["timestamp"] = pred["timestamp"].isoformat()
        
        return jsonify({
            "predictions": predictions,
            "success": True
        })
        
    except Exception as e:
        print(f"History retrieval error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/cvss/predict', methods=['POST'])
def predict_cvss():
    """Predict CVSS score based on vulnerability parameters"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['access_vector', 'access_complexity', 'authentication', 
                          'confidentiality', 'integrity', 'availability']
        
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Use the CVSS predictor
        if not cvss_predictor:
            return jsonify({
                'success': False,
                'error': 'CVSS predictor not available'
            }), 500
        
        # Prepare input data for the predictor with correct mapping
        input_data = {
            'cwe_code': data.get('cwe', 0),
            'access_vector': data['access_vector'],
            'access_complexity': data['access_complexity'],
            'access_authentication': data['authentication'],
            'impact_confidentiality': data['confidentiality'],
            'impact_integrity': data['integrity'],
            'impact_availability': data['availability'],
            'summary': data.get('summary', '')
        }
        
        # Make prediction
        prediction = cvss_predictor.predict(input_data)
        
        # Save assessment to database
        assessment_record = {
            'timestamp': datetime.utcnow(),
            'cwe': data.get('cwe', ''),
            'access_vector': data['access_vector'],
            'access_complexity': data['access_complexity'],
            'authentication': data['authentication'],
            'confidentiality': data['confidentiality'],
            'integrity': data['integrity'],
            'availability': data['availability'],
            'summary': data.get('summary', ''),
            'cvss_score': prediction.get('cvss_score', 0),
            'risk_level': prediction.get('risk_level', 'Unknown'),
            'model_used': prediction.get('model_used', 'Unknown')
        }
        
        # Add details if available
        if 'details' in prediction:
            assessment_record.update({
                'exploitability_score': prediction['details'].get('exploitability', 0),
                'impact_score': prediction['details'].get('impact', 0)
            })
        
        try:
            db.cvss_assessments.insert_one(assessment_record)
        except Exception as e:
            print(f"Warning: Could not save to database: {e}")
        
        return jsonify({
            'success': True,
            **prediction
        })
        
    except Exception as e:
        print(f"Error in CVSS prediction: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/cvss/history', methods=['GET'])
def get_cvss_history():
    """Get CVSS assessment history"""
    try:
        # Get assessments from database, sorted by timestamp (newest first)
        assessments = list(db.cvss_assessments.find(
            {},
            {'_id': 0}  # Exclude MongoDB _id field
        ).sort('timestamp', -1).limit(100))  # Limit to last 100 assessments
        
        return jsonify({
            'success': True,
            'assessments': assessments
        })
        
    except Exception as e:
        print(f"Error retrieving CVSS history: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'assessments': []
        }), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get CVSS assessments for statistics
        assessments = list(db.cvss_assessments.find({}, {'_id': 0}))
        
        if not assessments:
            return jsonify({
                'success': True,
                'stats': {
                    'total_vulnerabilities': 0,
                    'average_cvss_score': 0,
                    'highest_risk': 'None',
                    'risk_index': 0,
                    'risk_distribution': {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
                }
            })
        
        # Calculate statistics
        total_vulnerabilities = len(assessments)
        average_cvss_score = sum(a['cvss_score'] for a in assessments) / total_vulnerabilities
        
        # Risk distribution
        risk_distribution = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for assessment in assessments:
            risk_category = assessment['risk_category']
            if risk_category in risk_distribution:
                risk_distribution[risk_category] += 1
        
        # Highest risk
        highest_risk = 'Low'
        if risk_distribution['Critical'] > 0:
            highest_risk = 'Critical'
        elif risk_distribution['High'] > 0:
            highest_risk = 'High'
        elif risk_distribution['Medium'] > 0:
            highest_risk = 'Medium'
        
        # Risk index (weighted average)
        risk_weights = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        total_weight = sum(risk_distribution[risk] * risk_weights[risk] for risk in risk_distribution)
        risk_index = (total_weight / total_vulnerabilities) * 25 if total_vulnerabilities > 0 else 0
        
        return jsonify({
            'success': True,
            'stats': {
                'total_vulnerabilities': total_vulnerabilities,
                'average_cvss_score': round(average_cvss_score, 1),
                'highest_risk': highest_risk,
                'risk_index': round(risk_index, 1),
                'risk_distribution': risk_distribution
            }
        })
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'models': {
            'insurance_model': insurance_model is not None,
            'cvss_model': cvss_model is not None,
            'tfidf_vectorizer': tfidf_vectorizer is not None,
            'onehot_encoder': onehot_encoder is not None,
            'expert_rf_model': expert_rf_model is not None,
            'expert_encoders': expert_encoders is not None
        },
        'database': 'connected' if mongo_client else 'disconnected'
    }
    return jsonify(status)

# Expert-based Risk Assessment Countermeasures Dictionary
countermeasures = {
    "Info Sec Policy Availability": {
        "No": {
            "countermeasure": "Develop, document, and enforce an information security policy aligned with organizational goals. Conduct regular reviews and updates.",
            "reference": "https://attack.mitre.org/techniques/T1589/"
        }
    },
    "Incident Response Plan": {
        "No": {
            "countermeasure": "Establish and test an incident response plan to quickly detect, respond, and recover from incidents. Train staff on their roles.",
            "reference": "https://attack.mitre.org/techniques/T1609/"
        }
    },
    "Incident Plan Testing": {
        "Never": {
            "countermeasure": "Increase testing frequency to at least monthly for effectiveness; perform tabletop exercises and live drills.",
            "reference": "https://attack.mitre.org/techniques/T1620/"
        },
        "Annually": {
            "countermeasure": "Increase testing frequency to at least monthly for effectiveness; perform tabletop exercises and live drills.",
            "reference": "https://attack.mitre.org/techniques/T1620/"
        },
        "Quarterly": {
            "countermeasure": "Increase testing frequency to at least monthly for effectiveness; perform tabletop exercises and live drills.",
            "reference": "https://attack.mitre.org/techniques/T1620/"
        }
    },
    "Physical Access Control Implementation": {
        "Partially Implemented": {
            "countermeasure": "Implement strict physical access controls such as badge readers, biometric scanners, surveillance, and visitor logs.",
            "reference": "https://attack.mitre.org/techniques/T1078/"
        },
        "Not Implemented": {
            "countermeasure": "Implement strict physical access controls such as badge readers, biometric scanners, surveillance, and visitor logs.",
            "reference": "https://attack.mitre.org/techniques/T1078/"
        }
    },
    "Remote Access Security Measures": {
        "VPN": {
            "countermeasure": "Use Multi-Factor Authentication (MFA) with VPN and remote access. Monitor and restrict remote access.",
            "reference": "https://attack.mitre.org/techniques/T1110/"
        },
        "None": {
            "countermeasure": "Use Multi-Factor Authentication (MFA) with VPN and remote access. Monitor and restrict remote access.",
            "reference": "https://attack.mitre.org/techniques/T1110/"
        }
    },
    "Backup and Recovery Procedures": {
        "Irregular": {
            "countermeasure": "Establish regular backups with tested recovery processes. Maintain offline or immutable backups.",
            "reference": "https://attack.mitre.org/techniques/T1486/"
        }
    },
    "Employee Training on Information Security": {
        "Occasionally": {
            "countermeasure": "Conduct regular, comprehensive security awareness training covering phishing, social engineering, and policies.",
            "reference": "https://attack.mitre.org/techniques/T1566/"
        },
        "Never": {
            "countermeasure": "Conduct regular, comprehensive security awareness training covering phishing, social engineering, and policies.",
            "reference": "https://attack.mitre.org/techniques/T1566/"
        }
    },
    "Data Encryption Practice": {
        "At Rest": {
            "countermeasure": "Implement encryption both at rest and in transit using strong, modern algorithms and key management.",
            "reference": "https://attack.mitre.org/techniques/T1027/"
        },
        "In Transit": {
            "countermeasure": "Implement encryption both at rest and in transit using strong, modern algorithms and key management.",
            "reference": "https://attack.mitre.org/techniques/T1027/"
        },
        "None": {
            "countermeasure": "Implement encryption both at rest and in transit using strong, modern algorithms and key management.",
            "reference": "https://attack.mitre.org/techniques/T1027/"
        }
    },
    "Antivirus Software": {
        "No": {
            "countermeasure": "Deploy and regularly update antivirus/endpoint detection and response (EDR) solutions to detect malware and anomalies.",
            "reference": "https://attack.mitre.org/techniques/T1059/"
        }
    },
    "Vulnerability Scanning Frequency": {
        "Never": {
            "countermeasure": "Implement continuous or monthly vulnerability scanning and timely patch management processes.",
            "reference": "https://attack.mitre.org/techniques/T1203/"
        },
        "Quarterly": {
            "countermeasure": "Implement continuous or monthly vulnerability scanning and timely patch management processes.",
            "reference": "https://attack.mitre.org/techniques/T1203/"
        },
        "Annually": {
            "countermeasure": "Implement continuous or monthly vulnerability scanning and timely patch management processes.",
            "reference": "https://attack.mitre.org/techniques/T1203/"
        }
    },
    "Risk Assessment Frequency": {
        "Never": {
            "countermeasure": "Conduct quarterly risk assessments to identify, evaluate, and mitigate emerging threats promptly.",
            "reference": "https://attack.mitre.org/techniques/T1592/"
        },
        "Annually": {
            "countermeasure": "Conduct quarterly risk assessments to identify, evaluate, and mitigate emerging threats promptly.",
            "reference": "https://attack.mitre.org/techniques/T1592/"
        },
        "Biannually": {
            "countermeasure": "Conduct quarterly risk assessments to identify, evaluate, and mitigate emerging threats promptly.",
            "reference": "https://attack.mitre.org/techniques/T1592/"
        }
    },
    "Incident Reporting Mechanism": {
        "Informal Reporting": {
            "countermeasure": "Establish formal incident reporting processes with clear channels and responsibilities.",
            "reference": "https://attack.mitre.org/techniques/T1195/"
        },
        "None": {
            "countermeasure": "Establish formal incident reporting processes with clear channels and responsibilities.",
            "reference": "https://attack.mitre.org/techniques/T1195/"
        }
    },
    "Third-party Risk Management": {
        "Does Not Exist": {
            "countermeasure": "Develop third-party risk management program to assess and monitor supply chain and vendor risks.",
            "reference": "https://attack.mitre.org/techniques/T1195/"
        }
    },
    "Compliance Monitoring Frequency": {
        "Quarterly": {
            "countermeasure": "Implement continuous compliance monitoring to detect and remediate non-compliance rapidly.",
            "reference": "https://attack.mitre.org/techniques/T1086/"
        },
        "Annually": {
            "countermeasure": "Implement continuous compliance monitoring to detect and remediate non-compliance rapidly.",
            "reference": "https://attack.mitre.org/techniques/T1086/"
        },
        "None": {
            "countermeasure": "Implement continuous compliance monitoring to detect and remediate non-compliance rapidly.",
            "reference": "https://attack.mitre.org/techniques/T1086/"
        }
    },
    "Information Asset Inventory": {
        "Nonexistence": {
            "countermeasure": "Maintain and regularly update an asset inventory to track all hardware, software, and data assets.",
            "reference": "https://attack.mitre.org/techniques/T1592/"
        }
    },
    "Business Continuity Management": {
        "Partially Implemented": {
            "countermeasure": "Develop, test, and maintain business continuity and disaster recovery plans.",
            "reference": "https://attack.mitre.org/techniques/T1486/"
        },
        "Not Implemented": {
            "countermeasure": "Develop, test, and maintain business continuity and disaster recovery plans.",
            "reference": "https://attack.mitre.org/techniques/T1486/"
        }
    },
    "Security Audit History": {
        "Occasional": {
            "countermeasure": "Perform regular security audits and penetration tests to identify weaknesses and verify controls.",
            "reference": "https://attack.mitre.org/techniques/T1595/"
        },
        "Never": {
            "countermeasure": "Perform regular security audits and penetration tests to identify weaknesses and verify controls.",
            "reference": "https://attack.mitre.org/techniques/T1595/"
        }
    }
}

# User Authentication Endpoints
@app.route('/api/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({'error': 'User already exists'}), 409
        
        # Explicitly use pbkdf2:sha256 hashing method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        user_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (id, username, email, password)
            VALUES (?, ?, ?, ?)''', (user_id, username, email, hashed_password))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'User created successfully',
            'user_id': user_id
        }), 201
            
    except Exception as e:
        print(f"Exception during signup: {type(e).__name__} - {str(e)}")
        print(traceback.format_exc()) 
        return jsonify({'error': 'An internal server error occurred. Please check server logs.'}), 500

@app.route('/api/signin', methods=['POST'])
def signin():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find user
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return jsonify({
                'message': 'Login successful',
                'user_id': user[0],
                'username': user[1]
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# Expert-based Risk Assessment Endpoints
@app.route('/api/expert-risk-predict', methods=['POST'])
def expert_risk_predict():
    """Expert-based risk assessment prediction endpoint"""
    try:
        if not expert_rf_model or not expert_encoders:
            return jsonify({'error': 'Expert risk assessment models not loaded'}), 500
        
        data = request.get_json()
        
        # Required fields for expert risk assessment
        required_fields = [
            'organization_size', 'industry_type', 'info_sec_policy_availability',
            'incident_response_plan', 'incident_plan_testing', 'physical_access_control_implementation',
            'remote_access_security_measures', 'backup_and_recovery_procedures',
            'employee_training_on_information_security', 'data_encryption_practice',
            'antivirus_software', 'vulnerability_scanning_frequency', 'risk_assessment_frequency',
            'incident_reporting_mechanism', 'third_party_risk_management',
            'compliance_monitoring_frequency', 'information_asset_inventory',
            'business_continuity_management', 'security_audit_history',
            'no_of_employees'  # Added the assumed missing numerical feature
        ]
        
        # Check for missing fields
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {missing_fields}'}), 400
        
        # Check if we're using the rule-based fallback model
        if expert_model_method == 'rule-based':
            # Use rule-based calculation
            risk_level_index = calculate_rule_based_risk(data)
            risk_levels = ['Low', 'Medium', 'High']
            risk_level = risk_levels[risk_level_index]
            prediction = risk_level_index
            
            # Generate rule-based probabilities
            if risk_level_index == 0:  # Low risk
                prediction_proba = [0.7, 0.25, 0.05]
            elif risk_level_index == 1:  # Medium risk
                prediction_proba = [0.2, 0.6, 0.2]
            else:  # High risk
                prediction_proba = [0.05, 0.25, 0.7]
            
            confidence = max(prediction_proba) * 100
            
        else:
            # Use ML model prediction
            # Explicit mapping from API field names (snake_case) to expert_encoder keys (Title Case)
            api_to_encoder_key_map = {
                'organization_size': 'Organization Size',
                'industry_type': 'Sector Type',
                'info_sec_policy_availability': 'Info Sec Policy Availability',
                'incident_response_plan': 'Incident Response Plan',
                'incident_plan_testing': 'Incident Plan Testing',
                'physical_access_control_implementation': 'Physical Access Control Implementation',
                'remote_access_security_measures': 'Remote Access Security Measures',
                'backup_and_recovery_procedures': 'Backup and Recovery Procedures',
                'employee_training_on_information_security': 'Employee Training on Information Security',
                'data_encryption_practice': 'Data Encryption Practice',
                'antivirus_software': 'Antivirus Software',
                'vulnerability_scanning_frequency': 'Vulnerability Scanning Frequency',
                'risk_assessment_frequency': 'Risk Assessment Frequency',
                'incident_reporting_mechanism': 'Incident Reporting Mechanism',
                'third_party_risk_management': 'Third-party Risk Management',
                'compliance_monitoring_frequency': 'Compliance Monitoring Frequency',
                'information_asset_inventory': 'Information Asset Inventory',
                'business_continuity_management': 'Business Continuity Management',
                'security_audit_history': 'Security Audit History'
            }
            
            # Prepare data for prediction
            input_data = []
            for field in required_fields:
                value = data[field]
                
                if field == 'no_of_employees': # Handle numerical feature directly
                    try:
                        input_data.append(int(value))
                    except ValueError:
                        return jsonify({'error': f'Invalid value for no_of_employees: {value}. Must be an integer.'}), 400
                    continue # Move to the next field

                encoder_key = api_to_encoder_key_map.get(field)

                if encoder_key and encoder_key in expert_encoders:
                    encoder = expert_encoders[encoder_key]
                    if value not in encoder.classes_:
                        # Use the first class as default for unseen labels
                        value = encoder.classes_[0]
                    encoded_value = encoder.transform([value])[0]
                    input_data.append(encoded_value)
                else:
                    # This path should ideally not be taken if all required_fields are mapped
                    # and have corresponding encoders, and are meant to be categorical.
                    # If a field were intentionally numeric and not in encoders, this would be okay.
                    print(f"WARNING: No encoder found for field '{field}' (mapped to encoder key: '{encoder_key}'). Appending raw value: {value}")
                    input_data.append(value)
            
            # --- DEBUG PRINTS ---
            print(f"DEBUG: expert_encoders keys: {list(expert_encoders.keys())}")
            print(f"DEBUG: required_fields: {required_fields}")
            print(f"DEBUG: Input data before prediction: {input_data}")
            # --- END DEBUG PRINTS ---

            # Make prediction
            prediction = expert_rf_model.predict([input_data])[0]
            prediction_proba = expert_rf_model.predict_proba([input_data])[0]
            
            # Get risk level mapping
            risk_levels = ['Low', 'Medium', 'High']
            risk_level = risk_levels[prediction] if prediction < len(risk_levels) else 'Unknown'
            
            # Calculate confidence
            confidence = max(prediction_proba) * 100
        
        # Generate countermeasures based on input data
        applicable_countermeasures = []
        for field, value in data.items():
            field_name = field.replace('_', ' ').title()
            if field_name in countermeasures and value in countermeasures[field_name]:
                countermeasure_info = countermeasures[field_name][value]
                applicable_countermeasures.append({
                    'category': field_name,
                    'issue': value,
                    'countermeasure': countermeasure_info['countermeasure'],
                    'reference': countermeasure_info['reference']
                })
        
        result = {
            'risk_level': risk_level,
            'risk_score': int(prediction),
            'confidence': round(confidence, 2),
            'countermeasures': applicable_countermeasures,
            'prediction_method': expert_model_method,
            'input_data': data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Save to database if user is logged in
        if 'user_id' in session and mongo_client:
            result['user_id'] = session['user_id']
            db.risk_assessments.insert_one(result.copy())
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/risk-history', methods=['GET'])
def get_risk_history():
    """Get user's risk assessment history"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 401
        
        if not mongo_client:
            return jsonify({'error': 'Database not available'}), 500
        
        user_id = session['user_id']
        assessments = list(db.risk_assessments.find(
            {'user_id': user_id},
            {'_id': 0}  # Exclude MongoDB _id field
        ).sort('timestamp', -1))
        
        return jsonify({
            'assessments': assessments,
            'count': len(assessments)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/claims-packages', methods=['GET'])
def get_claims_packages():
    """Get available insurance packages based on risk level"""
    packages = {
        'Low': {
            'name': 'Basic Protection',
            'coverage': '$100,000',
            'premium': '$500/year',
            'features': ['Basic cyber liability', 'Data breach response', '24/7 support']
        },
        'Medium': {
            'name': 'Enhanced Protection',
            'coverage': '$500,000',
            'premium': '$1,500/year',
            'features': ['Comprehensive cyber liability', 'Business interruption', 'Regulatory fines', 'Forensic investigation']
        },
        'High': {
            'name': 'Premium Protection',
            'coverage': '$2,000,000',
            'premium': '$5,000/year',
            'features': ['Full cyber liability', 'Business interruption', 'Regulatory fines', 'Forensic investigation', 'Crisis management', 'Reputation management']
        }
    }
    return jsonify(packages), 200

@app.route('/api/select-package', methods=['POST'])
def select_insurance_package():
    """Select and save insurance package"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 401
        
        data = request.get_json()
        package_type = data.get('package_type')
        risk_level = data.get('risk_level')
        
        if not all([package_type, risk_level]):
            return jsonify({'error': 'Package type and risk level are required'}), 400
        
        if mongo_client:
            package_selection = {
                'user_id': session['user_id'],
                'package_type': package_type,
                'risk_level': risk_level,
                'selected_at': datetime.now()
            }
            db.package_selections.insert_one(package_selection)
            
            return jsonify({
                'message': 'Insurance package selected successfully',
                'package_type': package_type
            }), 200
        else:
            return jsonify({'error': 'Database not available'}), 500
            
    except Exception as e:
         return jsonify({'error': str(e)}), 500

# Tharindu's Sector-Based Risk Assessment Endpoint
@app.route('/api/sector-risk-predict', methods=['POST'])
def sector_risk_predict():
    """Sector-based risk assessment prediction endpoint"""
    try:
        data = request.get_json()
        
        # Attack Scenario Data
        attack_data = data.get('attack_scenario', {})
        required_attack_fields = [
            'attack_type', 'targeted_sector', 'attack_vector', 'estimated_revenue_loss',
            'estimated_downtime', 'data_sensitivity', 'attack_sophistication',
            'threat_actor_type', 'geographic_scope', 'regulatory_impact'
        ]
        
        # Company Profile Data
        company_data = data.get('company_profile', {})
        required_company_fields = [
            'industry_type', 'company_category', 'annual_revenue', 'employee_count',
            'geographic_presence', 'data_handling_volume', 'security_posture',
            'compliance_requirements', 'technology_adoption', 'business_model'
        ]
        
        # Check for missing fields
        missing_attack_fields = [field for field in required_attack_fields if field not in attack_data]
        missing_company_fields = [field for field in required_company_fields if field not in company_data]
        
        if missing_attack_fields or missing_company_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing_attack_fields': missing_attack_fields,
                'missing_company_fields': missing_company_fields
            }), 400
        
        # Sector-specific risk calculation algorithm
        def calculate_sector_risk(attack_data, company_data):
            # Base risk score calculation
            risk_score = 0
            
            # Attack scenario scoring (40% weight)
            attack_weights = {
                'attack_type': {'Malware': 8, 'Phishing': 7, 'Ransomware': 10, 'DDoS': 6, 'Insider Threat': 9},
                'attack_sophistication': {'Low': 3, 'Medium': 6, 'High': 9, 'Advanced': 10},
                'threat_actor_type': {'Script Kiddie': 3, 'Cybercriminal': 7, 'Nation State': 10, 'Insider': 8},
                'data_sensitivity': {'Low': 2, 'Medium': 5, 'High': 8, 'Critical': 10}
            }
            
            # Company profile scoring (60% weight)
            company_weights = {
                'security_posture': {'Poor': 10, 'Basic': 7, 'Good': 4, 'Excellent': 1},
                'company_category': {'Startup': 6, 'SME': 5, 'Enterprise': 7, 'Government': 9},
                'data_handling_volume': {'Low': 2, 'Medium': 5, 'High': 8, 'Very High': 10},
                'compliance_requirements': {'None': 8, 'Basic': 5, 'Moderate': 3, 'Strict': 1}
            }
            
            # Industry-specific multipliers
            industry_multipliers = {
                'Financial Services': 1.3,
                'Healthcare': 1.25,
                'Government': 1.2,
                'Energy': 1.15,
                'Technology': 1.1,
                'Manufacturing': 1.0,
                'Retail': 0.95,
                'Education': 0.9
            }
            
            # Calculate attack scenario score
            attack_score = 0
            for field, value in attack_data.items():
                if field in attack_weights and value in attack_weights[field]:
                    attack_score += attack_weights[field][value]
            
            # Calculate company profile score
            company_score = 0
            for field, value in company_data.items():
                if field in company_weights and value in company_weights[field]:
                    company_score += company_weights[field][value]
            
            # Apply industry multiplier
            industry = company_data.get('industry_type', 'Manufacturing')
            multiplier = industry_multipliers.get(industry, 1.0)
            
            # Combine scores with weights
            total_score = (attack_score * 0.4 + company_score * 0.6) * multiplier
            
            # Normalize to 0-100 scale
            normalized_score = min(100, max(0, (total_score / 10) * 10))
            
            return normalized_score
        
        # Calculate risk score
        risk_score = calculate_sector_risk(attack_data, company_data)
        
        # Determine risk level
        if risk_score <= 30:
            risk_level = 'Low'
        elif risk_score <= 60:
            risk_level = 'Medium'
        elif risk_score <= 80:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        # Generate sector-specific recommendations
        def generate_recommendations(attack_data, company_data, risk_level):
            recommendations = []
            
            industry = company_data.get('industry_type', '')
            security_posture = company_data.get('security_posture', '')
            attack_type = attack_data.get('attack_type', '')
            
            # Industry-specific recommendations
            if industry == 'Financial Services':
                recommendations.extend([
                    'Implement advanced fraud detection systems',
                    'Enhance customer authentication mechanisms',
                    'Comply with PCI DSS and banking regulations'
                ])
            elif industry == 'Healthcare':
                recommendations.extend([
                    'Secure patient data with HIPAA compliance',
                    'Implement medical device security protocols',
                    'Establish incident response for patient safety'
                ])
            elif industry == 'Government':
                recommendations.extend([
                    'Implement zero-trust architecture',
                    'Enhance classified data protection',
                    'Establish inter-agency security coordination'
                ])
            
            # Attack-type specific recommendations
            if attack_type == 'Ransomware':
                recommendations.extend([
                    'Implement immutable backup solutions',
                    'Deploy advanced endpoint detection',
                    'Establish ransomware response procedures'
                ])
            elif attack_type == 'Phishing':
                recommendations.extend([
                    'Enhance email security gateways',
                    'Implement user awareness training',
                    'Deploy anti-phishing technologies'
                ])
            
            # Security posture improvements
            if security_posture in ['Poor', 'Basic']:
                recommendations.extend([
                    'Conduct comprehensive security assessment',
                    'Implement security framework (NIST, ISO 27001)',
                    'Establish security governance program'
                ])
            
            return recommendations
        
        recommendations = generate_recommendations(attack_data, company_data, risk_level)
        
        # Key risk factors identification
        key_factors = []
        if company_data.get('security_posture') in ['Poor', 'Basic']:
            key_factors.append('Weak security posture')
        if attack_data.get('attack_sophistication') in ['High', 'Advanced']:
            key_factors.append('High attack sophistication')
        if company_data.get('data_handling_volume') in ['High', 'Very High']:
            key_factors.append('Large data exposure')
        if attack_data.get('data_sensitivity') in ['High', 'Critical']:
            key_factors.append('Sensitive data at risk')
        
        result = {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'key_risk_factors': key_factors,
            'recommendations': recommendations,
            'attack_scenario': attack_data,
            'company_profile': company_data,
            'industry_analysis': {
                'industry': company_data.get('industry_type'),
                'sector_risk_rating': risk_level,
                'industry_specific_threats': [
                    f"{attack_data.get('attack_type')} targeting {company_data.get('industry_type')} sector"
                ]
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Save to database if user is logged in
        if 'user_id' in session and mongo_client:
            result['user_id'] = session['user_id']
            db.sector_assessments.insert_one(result.copy())
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login.html')
def serve_login_page():
    return send_from_directory(os.path.join(app.root_path, 'cvss-risk-dashboard'), 'login.html')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001, use_reloader=False)