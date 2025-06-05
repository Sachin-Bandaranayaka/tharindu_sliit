from flask import Flask, request, jsonify, render_template, send_from_directory
from datetime import datetime
import os
import traceback
import pickle
import numpy as np
import pandas as pd
from pymongo import MongoClient
import joblib

# Import the CVSS predictor
from cvss_predictor import predictor as cvss_predictor

app = Flask(__name__, static_folder=None)

# Load insurance model
try:
    insurance_model = joblib.load("models/final_claim_fee_predictor.pkl")
    insurance_feature_names = joblib.load("models/feature_names.pkl")
    print("Insurance model loaded successfully")
except Exception as e:
    print(f"Error loading insurance model: {e}")
    insurance_model = None
    insurance_feature_names = None

# Load CVSS model components
try:
    with open('models/cvss_model.pkl', 'rb') as file:
        cvss_model = pickle.load(file)
    with open('models/tfidf_vectorizer.pkl', 'rb') as file:
        tfidf_vectorizer = pickle.load(file)
    with open('models/onehot_encoder.pkl', 'rb') as file:
        onehot_encoder = pickle.load(file)
    print("CVSS model components loaded successfully")
except Exception as e:
    print(f"Error loading CVSS model components: {e}")
    cvss_model = None
    tfidf_vectorizer = None
    onehot_encoder = None

# MongoDB setup for insurance
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
    return send_from_directory('cvss-risk-dashboard', 'index.html')

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
    return jsonify({
        'status': 'healthy',
        'cvss_predictor': 'loaded' if cvss_predictor else 'not loaded',
        'insurance_model': 'loaded' if insurance_model else 'not loaded',
        'database': 'connected' if db else 'not connected'
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)