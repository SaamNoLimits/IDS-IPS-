"""
Quick deployment script for Enhanced IDS Model
Usage: python deploy_model.py
"""

import tensorflow as tf
import pickle
import numpy as np
import pandas as pd

class EnhancedIDSPredictor:
    def __init__(self, model_path="enhanced_ids_model_99percent.h5", scaler_path="feature_scaler.pkl"):
        self.model = tf.keras.models.load_model(model_path)
        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)
        self.class_names = ["Benign", "DDoS", "Bruteforce", "Botnet"]

    def predict(self, data):
        """Make predictions on new data"""
        # Scale the data
        scaled_data = self.scaler.transform(data)
        # Get predictions
        predictions = self.model.predict(scaled_data)
        # Convert to class names
        predicted_classes = [self.class_names[i] for i in predictions.argmax(axis=1)]
        return predicted_classes, predictions

# Example usage:
# predictor = EnhancedIDSPredictor()
# classes, probabilities = predictor.predict(your_data)
