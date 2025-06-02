#!/usr/bin/env python3
"""
CVSS Score Prediction Module
This module loads ML models and provides prediction functionality
for CVSS score assessment based on vulnerability metadata.
"""

import pickle
import os
import sys
import traceback

# Check for required dependencies
SKLEARN_AVAILABLE = False
NUMPY_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    print("Warning: NumPy is not available - using fallback calculation")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import OneHotEncoder
    SKLEARN_AVAILABLE = True
except ImportError:
    print("Warning: scikit-learn is not available - using fallback calculation")

# Model file paths
MODEL_PATH = os.path.join('models', 'cvss_model.pkl')
ENCODER_PATH = os.path.join('models', 'onehot_encoder.pkl')
VECTORIZER_PATH = os.path.join('models', 'tfidf_vectorizer.pkl')

class CVSSPredictor:
    """
    Provides functionality to predict CVSS scores using the pre-trained
    model and supporting transformers.
    """
    
    def __init__(self):
        """Initialize the predictor by loading the necessary ML artifacts."""
        self.is_loaded = False
        self.using_fallback = False
        
        # Check if required dependencies are available
        if not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
            self.using_fallback = True
            print("Using fallback prediction - missing required dependencies")
            return
            
        try:
            self._load_models()
            self.is_loaded = True
            print("CVSS Predictor initialized successfully")
        except Exception as e:
            print(f"Failed to initialize CVSS Predictor: {str(e)}")
            self.using_fallback = True
    
    def _load_models(self):
        """Load the ML models and transformers from disk."""
        # Load the trained model
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as file:
                self.model = pickle.load(file)
        else:
            raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
        
        # Load the TF-IDF vectorizer
        if os.path.exists(VECTORIZER_PATH):
            with open(VECTORIZER_PATH, 'rb') as file:
                self.tfidf_vectorizer = pickle.load(file)
        else:
            raise FileNotFoundError(f"Vectorizer file not found: {VECTORIZER_PATH}")
        
        # Load the OneHotEncoder
        if os.path.exists(ENCODER_PATH):
            with open(ENCODER_PATH, 'rb') as file:
                self.encoder = pickle.load(file)
        else:
            raise FileNotFoundError(f"Encoder file not found: {ENCODER_PATH}")
    
    def predict(self, input_data):
        """
        Predict CVSS score based on input vulnerability data.
        
        Args:
            input_data (dict): Dictionary containing vulnerability parameters
        
        Returns:
            dict: Prediction results including CVSS score and risk level
        """
        if self.using_fallback or not self.is_loaded:
            return self._fallback_prediction(input_data)
        
        try:
            # Extract parameters with defaults
            cwe_code = input_data.get('cwe_code', 0)
            access_authentication = input_data.get('access_authentication', 'None')
            access_complexity = input_data.get('access_complexity', 'Low')
            access_vector = input_data.get('access_vector', 'Network')
            impact_availability = input_data.get('impact_availability', 'None')
            impact_confidentiality = input_data.get('impact_confidentiality', 'None')
            impact_integrity = input_data.get('impact_integrity', 'None')
            summary = input_data.get('summary', '')
            
            # Prepare the input data for OneHotEncoder
            categorical_data = {
                'cwe_code': [cwe_code],
                'access_authentication': [access_authentication],
                'access_complexity': [access_complexity],
                'access_vector': [access_vector],
                'impact_availability': [impact_availability],
                'impact_confidentiality': [impact_confidentiality],
                'impact_integrity': [impact_integrity],
            }
            
            # Convert to DataFrame
            import pandas as pd
            input_df = pd.DataFrame(categorical_data)
            
            # One-hot encode the categorical features
            encoded_features = self.encoder.transform(input_df[['access_authentication', 'access_complexity', 'access_vector',
                                                               'impact_availability', 'impact_confidentiality', 
                                                               'impact_integrity']])
            encoded_df = pd.DataFrame(encoded_features, columns=self.encoder.get_feature_names_out())
            
            # Transform the summary text using the TF-IDF vectorizer
            summary_features = self.tfidf_vectorizer.transform([summary])
            tfidf_summary_df = pd.DataFrame(summary_features.toarray(), columns=self.tfidf_vectorizer.get_feature_names_out())
            
            # Combine the input data with the encoded features and TF-IDF features
            input_data_combined = pd.concat([input_df[['cwe_code']], encoded_df, tfidf_summary_df], axis=1)
            
            # Make prediction
            prediction = self.model.predict(input_data_combined)[0]
            
            # Validate prediction result and handle NaN/invalid values
            if prediction is None or np.isnan(prediction) or np.isinf(prediction):
                print(f"Warning: Invalid prediction result: {prediction}, using fallback calculation")
                return self._fallback_prediction(input_data)
            
            # Ensure prediction is within valid CVSS range (0-10)
            prediction = max(0.0, min(10.0, float(prediction)))
            
            # Determine risk level
            if prediction >= 7.0:
                risk_level = "High"
                risk_color = "#dc3545"  # Red
            elif prediction >= 4.0:
                risk_level = "Medium"
                risk_color = "#ffc107"  # Yellow
            else:
                risk_level = "Low"
                risk_color = "#28a745"  # Green
            
            # Calculate exploitability and impact scores
            exploitability = self._calculate_exploitability(access_vector, access_complexity, access_authentication)
            impact = self._calculate_impact(impact_confidentiality, impact_integrity, impact_availability)
            
            # Validate calculated scores
            if np.isnan(exploitability) or np.isinf(exploitability):
                exploitability = 0.0
            if np.isnan(impact) or np.isinf(impact):
                impact = 0.0
            
            return {
                "cvss_score": float(prediction),
                "risk_level": risk_level,
                "risk_color": risk_color,
                "success": True,
                "model_used": "ML Model",
                "details": {
                    "exploitability": exploitability,
                    "impact": impact,
                    "cwe_code": cwe_code
                }
            }
            
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            traceback.print_exc()
            return self._fallback_prediction(input_data)
    
    def _calculate_exploitability(self, access_vector, access_complexity, access_authentication):
        """Calculate exploitability subscore."""
        # Simplified exploitability calculation
        av_score = {"Local": 0.395, "Adjacent Network": 0.646, "Network": 1.0}.get(access_vector, 0.5)
        ac_score = {"High": 0.35, "Medium": 0.61, "Low": 0.71}.get(access_complexity, 0.5)
        au_score = {"Multiple": 0.45, "Single": 0.56, "None": 0.704}.get(access_authentication, 0.5)
        
        return round(20 * av_score * ac_score * au_score, 2)
    
    def _calculate_impact(self, confidentiality, integrity, availability):
        """Calculate impact score based on CIA triad"""
        impact_weights = {
            'None': 0.0,
            'Partial': 0.275,
            'Complete': 0.660
        }
        
        conf_impact = impact_weights.get(confidentiality, 0.0)
        int_impact = impact_weights.get(integrity, 0.0)
        avail_impact = impact_weights.get(availability, 0.0)
        
        # Calculate impact subscore
        impact = 10.41 * (1 - (1 - conf_impact) * (1 - int_impact) * (1 - avail_impact))
        return round(impact, 1)
    
    def _fallback_prediction(self, input_data):
        """
        Provide a fallback prediction when ML models are not available.
        Uses a simplified heuristic-based approach.
        """
        try:
            # Extract key parameters
            access_vector = input_data.get('access_vector', 'Network')
            access_complexity = input_data.get('access_complexity', 'Low')
            access_authentication = input_data.get('access_authentication', 'None')
            impact_availability = input_data.get('impact_availability', 'None')
            impact_confidentiality = input_data.get('impact_confidentiality', 'None')
            impact_integrity = input_data.get('impact_integrity', 'None')
            
            # Simple scoring based on parameters
            score = 0.0
            
            # Access Vector scoring
            if access_vector == 'Network':
                score += 3.0
            elif access_vector == 'Adjacent Network':
                score += 2.0
            else:  # Local
                score += 1.0
            
            # Access Complexity scoring
            if access_complexity == 'Low':
                score += 2.0
            elif access_complexity == 'Medium':
                score += 1.5
            else:  # High
                score += 1.0
            
            # Authentication scoring
            if access_authentication == 'None':
                score += 2.0
            elif access_authentication == 'Single':
                score += 1.0
            else:  # Multiple
                score += 0.5
            
            # Impact scoring
            impact_scores = {'Complete': 2.0, 'Partial': 1.0, 'None': 0.0}
            score += impact_scores.get(impact_confidentiality, 0.0)
            score += impact_scores.get(impact_integrity, 0.0)
            score += impact_scores.get(impact_availability, 0.0)
            
            # Normalize to 0-10 scale
            cvss_score = min(10.0, max(0.0, score))
            
            # Determine risk level
            if cvss_score >= 7.0:
                risk_level = "High"
                risk_color = "#dc3545"
            elif cvss_score >= 4.0:
                risk_level = "Medium"
                risk_color = "#ffc107"
            else:
                risk_level = "Low"
                risk_color = "#28a745"
            
            return {
                "cvss_score": round(cvss_score, 1),
                "risk_level": risk_level,
                "risk_color": risk_color,
                "success": True,
                "model_used": "Fallback Heuristic",
                "warning": "Using simplified calculation - ML models not available",
                "details": {
                    "exploitability": self._calculate_exploitability(access_vector, access_complexity, access_authentication),
                    "impact": self._calculate_impact(impact_confidentiality, impact_integrity, impact_availability)
                }
            }
            
        except Exception as e:
            print(f"Fallback prediction error: {str(e)}")
            return {
                "cvss_score": 5.0,
                "risk_level": "Medium",
                "risk_color": "#ffc107",
                "success": False,
                "error": str(e),
                "model_used": "Default"
            }

# Create a global instance
predictor = CVSSPredictor()