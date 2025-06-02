import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_squared_error, r2_score
import joblib
import os

def retrain_insurance_model():
    print("Loading dataset...")
    # Load the dataset
    df = pd.read_csv('models/Large_Sample_Claim_Request_and_Calculation_Dataset.csv')
    
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Select features for training
    feature_columns = [
        'Incurred Loss Amount',
        'Requested Coverage Percentage', 
        'Deductible',
        'Coverage Limit',
        'Coverage Percentage',
        'Verified Incurred Loss Amount',
        'Loss After Deductible',
        'Capped Loss'
    ]
    
    # Target variable
    target_column = 'Final Claim Fee'
    
    # Check if all required columns exist
    missing_cols = [col for col in feature_columns + [target_column] if col not in df.columns]
    if missing_cols:
        print(f"Missing columns: {missing_cols}")
        return False
    
    # Prepare the data
    X = df[feature_columns].copy()
    y = df[target_column].copy()
    
    # Handle missing values
    X = X.fillna(X.median())
    y = y.fillna(y.median())
    
    # Remove any infinite values
    X = X.replace([np.inf, -np.inf], np.nan).fillna(X.median())
    y = y.replace([np.inf, -np.inf], np.nan).fillna(y.median())
    
    print(f"Features shape: {X.shape}")
    print(f"Target shape: {y.shape}")
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print("Training the model...")
    # Train a Random Forest model
    model = RandomForestRegressor(
        n_estimators=100,
        random_state=42,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    print(f"Model Performance:")
    print(f"MSE: {mse:.2f}")
    print(f"R2 Score: {r2:.4f}")
    
    # Save the model and feature names
    print("Saving the model...")
    joblib.dump(model, 'models/final_claim_fee_predictor.pkl')
    joblib.dump(feature_columns, 'models/feature_names.pkl')
    
    print("Model retrained and saved successfully!")
    return True

if __name__ == "__main__":
    success = retrain_insurance_model()
    if success:
        print("\nModel retraining completed successfully!")
        print("The Flask app should now be able to load the insurance model.")
    else:
        print("\nModel retraining failed. Please check the dataset and try again.")