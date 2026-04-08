# ml_model.py

import joblib
import os

class MLModel:
    def __init__(self, model_path):
        """
        Initialize the ML model by loading a pre-trained Random Forest from a .pkl file.

        Args:
            model_path (str): Path to the trained model file
        """
        # Ensure the path is relative to this file
        self.model_path = os.path.join(os.path.dirname(__file__), model_path)
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        
        # Load the trained model
        self.model = joblib.load(self.model_path)

    def predict(self, features):
        """
        Make a prediction on a single flow or batch of flows.

        Args:
            features (list of list of floats): Each inner list is one flow's features.

        Returns:
            list: Predictions, 0 = benign, 1 = malicious.
        """
        return self.model.predict(features)
    
    def predict_proba(self, features):
        return self.model.predict_proba(features)