import gradio as gr
import joblib
import numpy as np
import json
import os

# Load model and scaler
# Note: These files must be uploaded to the HF Space 'models/' directory
try:
    with open("models/feature_order.json", "r") as f:
        feature_names = json.load(f)["features"]
    
    scaler = joblib.load("models/scaler.joblib")
    model = joblib.load("models/stacking_ensemble.joblib")
    
    # Check if we have base models for the stacking classifier
    # If using StackingClassifier from sklearn, it might need base models accessible
except Exception as e:
    print(f"Error loading model: {e}")
    # Fallback to RF if stacking fails or is missing
    try:
        model = joblib.load("models/rf.joblib")
    except:
        model = None

def predict(feature_json):
    if model is None:
        return json.dumps({"error": "Model not loaded on server"})
        
    try:
        import pandas as pd
        features = json.loads(feature_json)
        
        # Create a DataFrame with the correct feature names
        X_df = pd.DataFrame([features], columns=feature_names)
        
        # Transform using DataFrame
        X_scaled_arr = scaler.transform(X_df)
        
        # Convert back to DataFrame to preserve feature names and suppress UserWarning
        X_scaled = pd.DataFrame(X_scaled_arr, columns=feature_names)
        
        # Predict using scaled DataFrame
        prob = float(model.predict_proba(X_scaled)[0][1])
        pred = int(model.predict(X_scaled)[0])
        
        # Confidence logic
        conf = prob if pred == 1 else (1 - prob)
        
        return json.dumps({
            "prediction": pred,
            "probability": prob,
            "confidence": conf,
            "error": None
        })
    except Exception as e:
        return json.dumps({"error": str(e)})

# Gradio Interface
iface = gr.Interface(
    fn=predict,
    inputs=gr.Textbox(label="Feature Vector (JSON String)"),
    outputs=gr.Textbox(label="Result (JSON String)"),
    title="PhishGuard ML Engine",
    description="Backend inference engine for PhishGuard v2"
)

if __name__ == "__main__":
    iface.launch()
