import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle

class ModelTrainer:
    """
    Trains and evaluates multiple machine learning models for phishing detection.
    """
    
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2
            ),
            'SVM': SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                random_state=42,
                probability=True
            ),
            'Logistic Regression': LogisticRegression(
                random_state=42,
                max_iter=1000,
                C=1.0
            )
        }
        
        self.scalers = {}
        self.trained_models = {}
    
    def train_models(self, X_train, X_test, y_train, y_test, selected_algorithms):
        """
        Train selected machine learning models.
        
        Args:
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels
            selected_algorithms: List of algorithm names to train
            
        Returns:
            dict: Dictionary containing trained models and their performance metrics
        """
        results = {}
        
        for algo_name in selected_algorithms:
            if algo_name not in self.models:
                continue
                
            # Get the model
            model = self.models[algo_name]
            
            # Scale features for SVM and Logistic Regression
            if algo_name in ['SVM', 'Logistic Regression']:
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                self.scalers[algo_name] = scaler
            else:
                X_train_scaled = X_train
                X_test_scaled = X_test
            
            # Train the model
            model.fit(X_train_scaled, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test_scaled)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted')
            recall = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')
            
            # Cross-validation score
            cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
            
            # Classification report
            class_report = classification_report(y_test, y_pred, 
                                               target_names=['Legitimate', 'Phishing'])
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # Store results
            results[algo_name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': class_report,
                'confusion_matrix': cm,
                'predictions': y_pred
            }
            
            # Store trained model
            self.trained_models[algo_name] = model
        
        return results
    
    def predict_single_url(self, features, model_name):
        """
        Predict whether a single URL is phishing or legitimate.
        
        Args:
            features: Dictionary or array of URL features
            model_name: Name of the model to use for prediction
            
        Returns:
            tuple: (prediction, probability)
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not found. Available models: {list(self.trained_models.keys())}")
        
        model = self.trained_models[model_name]
        
        # Convert features to DataFrame if it's a dictionary
        if isinstance(features, dict):
            features_df = pd.DataFrame([features])
        else:
            features_df = features
        
        # Scale features if necessary
        if model_name in self.scalers:
            features_scaled = self.scalers[model_name].transform(features_df)
        else:
            features_scaled = features_df
        
        # Make prediction
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0]
        
        return prediction, probability
    
    def get_feature_importance(self, model_name):
        """
        Get feature importance for tree-based models.
        
        Args:
            model_name: Name of the model
            
        Returns:
            array: Feature importances
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not found.")
        
        model = self.trained_models[model_name]
        
        if hasattr(model, 'feature_importances_'):
            return model.feature_importances_
        else:
            raise ValueError(f"Model {model_name} does not support feature importance.")
    
    def save_models(self, filepath):
        """
        Save trained models to disk.
        
        Args:
            filepath: Path to save the models
        """
        model_data = {
            'models': self.trained_models,
            'scalers': self.scalers
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_models(self, filepath):
        """
        Load trained models from disk.
        
        Args:
            filepath: Path to load the models from
        """
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.trained_models = model_data['models']
        self.scalers = model_data['scalers']
    
    def get_model_summary(self):
        """
        Get a summary of all trained models.
        
        Returns:
            dict: Summary of model performance
        """
        summary = {}
        
        for model_name, model in self.trained_models.items():
            summary[model_name] = {
                'type': type(model).__name__,
                'parameters': model.get_params()
            }
        
        return summary
