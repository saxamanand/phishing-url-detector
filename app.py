import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import pickle
import os
from feature_extractor import URLFeatureExtractor
from model_trainer import ModelTrainer
from utils import generate_sample_data, validate_url

# Set page config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'models_trained' not in st.session_state:
    st.session_state.models_trained = False
if 'feature_extractor' not in st.session_state:
    st.session_state.feature_extractor = URLFeatureExtractor()
if 'model_trainer' not in st.session_state:
    st.session_state.model_trainer = ModelTrainer()

def main():
    st.title("🔒 Phishing URL Detector")
    st.markdown("### Machine Learning-Powered URL Security Analysis")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Home", "Dataset & Training", "Model Evaluation", "URL Testing", "Feature Analysis"]
    )
    
    if page == "Home":
        show_home()
    elif page == "Dataset & Training":
        show_dataset_training()
    elif page == "Model Evaluation":
        show_model_evaluation()
    elif page == "URL Testing":
        show_url_testing()
    elif page == "Feature Analysis":
        show_feature_analysis()

def show_home():
    st.header("Welcome to the Phishing URL Detector")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Features")
        st.write("""
        - **Comprehensive Feature Extraction**: 20+ URL characteristics
        - **Multiple ML Algorithms**: Random Forest, SVM, Logistic Regression
        - **Real-time URL Testing**: Instant phishing detection
        - **Feature Importance Analysis**: Understand what makes URLs suspicious
        - **Model Performance Metrics**: Accuracy, Precision, Recall, F1-Score
        """)
    
    with col2:
        st.subheader("🔧 How It Works")
        st.write("""
        1. **Feature Extraction**: Analyze URL structure and characteristics
        2. **Model Training**: Train multiple ML classifiers
        3. **Evaluation**: Compare model performance
        4. **Testing**: Test individual URLs for phishing detection
        5. **Analysis**: Understand feature importance and patterns
        """)
    
    st.subheader("🚀 Quick Start")
    st.write("1. Go to 'Dataset & Training' to train the models")
    st.write("2. Visit 'Model Evaluation' to see performance metrics")
    st.write("3. Use 'URL Testing' to test individual URLs")
    st.write("4. Explore 'Feature Analysis' to understand the model's decision process")

def show_dataset_training():
    st.header("📊 Dataset & Model Training")
    
    # Dataset section
    st.subheader("Dataset Information")
    
    if st.button("Generate Sample Dataset"):
        with st.spinner("Generating sample dataset..."):
            # Generate sample data for demonstration
            df = generate_sample_data(1000)
            st.session_state.dataset = df
            st.success("Sample dataset generated successfully!")
    
    if 'dataset' in st.session_state:
        df = st.session_state.dataset
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total URLs", len(df))
        with col2:
            st.metric("Phishing URLs", len(df[df['is_phishing'] == 1]))
        with col3:
            st.metric("Legitimate URLs", len(df[df['is_phishing'] == 0]))
        
        st.subheader("Dataset Preview")
        st.dataframe(df.head())
        
        # Feature extraction
        st.subheader("Feature Extraction")
        if st.button("Extract Features"):
            with st.spinner("Extracting features from URLs..."):
                features_list = []
                for url in df['url']:
                    features = st.session_state.feature_extractor.extract_features(url)
                    features_list.append(features)
                
                feature_df = pd.DataFrame(features_list)
                feature_df['is_phishing'] = df['is_phishing'].values
                st.session_state.feature_df = feature_df
                st.success("Features extracted successfully!")
        
        # Model training
        if 'feature_df' in st.session_state:
            st.subheader("Model Training")
            
            algorithms = st.multiselect(
                "Select algorithms to train:",
                ["Random Forest", "SVM", "Logistic Regression"],
                default=["Random Forest", "Logistic Regression"]
            )
            
            if st.button("Train Models"):
                if algorithms:
                    with st.spinner("Training models..."):
                        feature_df = st.session_state.feature_df
                        X = feature_df.drop('is_phishing', axis=1)
                        y = feature_df['is_phishing']
                        
                        # Split data
                        X_train, X_test, y_train, y_test = train_test_split(
                            X, y, test_size=0.2, random_state=42, stratify=y
                        )
                        
                        # Train models
                        results = st.session_state.model_trainer.train_models(
                            X_train, X_test, y_train, y_test, algorithms
                        )
                        
                        st.session_state.training_results = results
                        st.session_state.X_test = X_test
                        st.session_state.y_test = y_test
                        st.session_state.feature_names = X.columns.tolist()
                        st.session_state.models_trained = True
                        
                        st.success("Models trained successfully!")
                        
                        # Display training results
                        st.subheader("Training Results")
                        # Filter out non-serializable objects for display
                        display_results = {}
                        for model_name, model_data in results.items():
                            display_results[model_name] = {
                                'accuracy': model_data['accuracy'],
                                'precision': model_data['precision'],
                                'recall': model_data['recall'],
                                'f1_score': model_data['f1_score'],
                                'cv_mean': model_data['cv_mean'],
                                'cv_std': model_data['cv_std']
                            }
                        results_df = pd.DataFrame(display_results).T
                        st.dataframe(results_df)
                else:
                    st.error("Please select at least one algorithm to train.")

def show_model_evaluation():
    st.header("📈 Model Evaluation")
    
    if not st.session_state.models_trained:
        st.warning("Please train the models first in the 'Dataset & Training' section.")
        return
    
    results = st.session_state.training_results
    
    # Model comparison
    st.subheader("Model Performance Comparison")
    
    # Filter out non-serializable objects for display
    display_results = {}
    for model_name, model_data in results.items():
        display_results[model_name] = {
            'accuracy': model_data['accuracy'],
            'precision': model_data['precision'],
            'recall': model_data['recall'],
            'f1_score': model_data['f1_score'],
            'cv_mean': model_data['cv_mean'],
            'cv_std': model_data['cv_std']
        }
    metrics_df = pd.DataFrame(display_results).T
    
    # Display metrics table
    st.dataframe(metrics_df.style.highlight_max(axis=0))
    
    # Visualization
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Accuracy Comparison")
        fig, ax = plt.subplots(figsize=(10, 6))
        models = list(results.keys())
        accuracies = [results[model]['accuracy'] for model in models]
        bars = ax.bar(models, accuracies, color=['#1f77b4', '#ff7f0e', '#2ca02c'])
        ax.set_ylabel('Accuracy')
        ax.set_title('Model Accuracy Comparison')
        ax.set_ylim(0, 1)
        
        # Add value labels on bars
        for bar, acc in zip(bars, accuracies):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                   f'{acc:.3f}', ha='center', va='bottom')
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        st.subheader("F1-Score Comparison")
        fig, ax = plt.subplots(figsize=(10, 6))
        f1_scores = [results[model]['f1_score'] for model in models]
        bars = ax.bar(models, f1_scores, color=['#d62728', '#9467bd', '#8c564b'])
        ax.set_ylabel('F1-Score')
        ax.set_title('Model F1-Score Comparison')
        ax.set_ylim(0, 1)
        
        # Add value labels on bars
        for bar, f1 in zip(bars, f1_scores):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                   f'{f1:.3f}', ha='center', va='bottom')
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig)
    
    # Detailed model analysis
    st.subheader("Detailed Model Analysis")
    selected_model = st.selectbox("Select model for detailed analysis:", list(results.keys()))
    
    if selected_model:
        st.write(f"**{selected_model} Performance:**")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Accuracy", f"{results[selected_model]['accuracy']:.3f}")
        with col2:
            st.metric("Precision", f"{results[selected_model]['precision']:.3f}")
        with col3:
            st.metric("Recall", f"{results[selected_model]['recall']:.3f}")
        with col4:
            st.metric("F1-Score", f"{results[selected_model]['f1_score']:.3f}")
        
        # Classification report
        st.subheader("Classification Report")
        st.text(results[selected_model]['classification_report'])
        
        # Confusion matrix
        st.subheader("Confusion Matrix")
        cm = results[selected_model]['confusion_matrix']
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Legitimate', 'Phishing'],
                   yticklabels=['Legitimate', 'Phishing'])
        ax.set_ylabel('True Label')
        ax.set_xlabel('Predicted Label')
        ax.set_title(f'Confusion Matrix - {selected_model}')
        st.pyplot(fig)

def show_url_testing():
    st.header("🔍 URL Testing")
    
    if not st.session_state.models_trained:
        st.warning("Please train the models first in the 'Dataset & Training' section.")
        return
    
    st.subheader("Test Individual URLs")
    
    # URL input
    url_input = st.text_input("Enter a URL to test:", placeholder="https://example.com")
    
    if st.button("Analyze URL"):
        if url_input:
            if not validate_url(url_input):
                st.error("Please enter a valid URL.")
                return
            
            with st.spinner("Analyzing URL..."):
                # Extract features
                features = st.session_state.feature_extractor.extract_features(url_input)
                feature_df = pd.DataFrame([features])
                
                # Get predictions from all models
                results = st.session_state.training_results
                predictions = {}
                
                for model_name, model_data in results.items():
                    model = model_data['model']
                    prediction = model.predict(feature_df)[0]
                    probability = model.predict_proba(feature_df)[0]
                    predictions[model_name] = {
                        'prediction': prediction,
                        'probability': probability
                    }
                
                # Display results
                st.subheader("Analysis Results")
                
                # Overall assessment
                phishing_votes = sum(1 for p in predictions.values() if p['prediction'] == 1)
                total_models = len(predictions)
                
                if phishing_votes > total_models / 2:
                    st.error("🚨 **PHISHING DETECTED** - This URL appears to be malicious!")
                else:
                    st.success("✅ **LEGITIMATE** - This URL appears to be safe.")
                
                # Model predictions
                st.subheader("Individual Model Predictions")
                
                col1, col2, col3 = st.columns(3)
                cols = [col1, col2, col3]
                
                for i, (model_name, pred_data) in enumerate(predictions.items()):
                    with cols[i % 3]:
                        prediction = pred_data['prediction']
                        prob = pred_data['probability']
                        
                        if prediction == 1:
                            st.error(f"**{model_name}**: Phishing")
                            st.write(f"Confidence: {prob[1]:.2%}")
                        else:
                            st.success(f"**{model_name}**: Legitimate")
                            st.write(f"Confidence: {prob[0]:.2%}")
                
                # Feature breakdown
                st.subheader("URL Feature Analysis")
                
                feature_names = st.session_state.feature_names
                feature_values = [features[name] for name in feature_names]
                
                feature_analysis_df = pd.DataFrame({
                    'Feature': feature_names,
                    'Value': feature_values
                })
                
                st.dataframe(feature_analysis_df)
                
                # URL characteristics
                st.subheader("URL Characteristics")
                st.write(f"**URL Length**: {features['url_length']}")
                st.write(f"**Domain Length**: {features['domain_length']}")
                st.write(f"**Number of Subdomains**: {features['num_subdomains']}")
                st.write(f"**Has IP Address**: {'Yes' if features['has_ip'] else 'No'}")
                st.write(f"**HTTPS**: {'Yes' if features['https'] else 'No'}")
                st.write(f"**Number of Special Characters**: {features['num_special_chars']}")
        else:
            st.error("Please enter a URL to analyze.")

def show_feature_analysis():
    st.header("🔬 Feature Analysis")
    
    if not st.session_state.models_trained:
        st.warning("Please train the models first in the 'Dataset & Training' section.")
        return
    
    # Feature importance analysis
    st.subheader("Feature Importance Analysis")
    
    results = st.session_state.training_results
    feature_names = st.session_state.feature_names
    
    # Select model for feature importance
    model_for_analysis = st.selectbox(
        "Select model for feature importance analysis:",
        [name for name in results.keys() if name != "SVM"]  # SVM doesn't have feature_importances_
    )
    
    if model_for_analysis:
        model = results[model_for_analysis]['model']
        
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            
            # Create feature importance dataframe
            importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': importances
            }).sort_values('Importance', ascending=False)
            
            # Display top features
            st.subheader("Top Important Features")
            st.dataframe(importance_df)
            
            # Visualization
            fig, ax = plt.subplots(figsize=(12, 8))
            top_features = importance_df.head(10)
            bars = ax.barh(top_features['Feature'], top_features['Importance'])
            ax.set_xlabel('Feature Importance')
            ax.set_title(f'Top 10 Feature Importances - {model_for_analysis}')
            ax.invert_yaxis()
            
            # Add value labels
            for bar, importance in zip(bars, top_features['Importance']):
                width = bar.get_width()
                ax.text(width + 0.001, bar.get_y() + bar.get_height()/2.,
                       f'{importance:.3f}', ha='left', va='center')
            
            plt.tight_layout()
            st.pyplot(fig)
        else:
            st.warning(f"{model_for_analysis} does not provide feature importance information.")
    
    # Feature correlation analysis
    if 'feature_df' in st.session_state:
        st.subheader("Feature Correlation Analysis")
        
        feature_df = st.session_state.feature_df
        correlation_matrix = feature_df.corr()
        
        # Select features for correlation analysis
        selected_features = st.multiselect(
            "Select features for correlation analysis:",
            feature_names,
            default=feature_names[:10]  # Show first 10 features by default
        )
        
        if selected_features:
            selected_corr = correlation_matrix.loc[selected_features, selected_features]
            
            fig, ax = plt.subplots(figsize=(12, 10))
            sns.heatmap(selected_corr, annot=True, cmap='coolwarm', center=0,
                       square=True, fmt='.2f')
            ax.set_title('Feature Correlation Matrix')
            plt.tight_layout()
            st.pyplot(fig)
    
    # Feature distribution analysis
    if 'feature_df' in st.session_state:
        st.subheader("Feature Distribution Analysis")
        
        feature_df = st.session_state.feature_df
        
        selected_feature = st.selectbox(
            "Select feature for distribution analysis:",
            feature_names
        )
        
        if selected_feature:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Distribution by class
            legitimate_data = feature_df[feature_df['is_phishing'] == 0][selected_feature]
            phishing_data = feature_df[feature_df['is_phishing'] == 1][selected_feature]
            
            ax1.hist(legitimate_data, bins=30, alpha=0.7, label='Legitimate', color='green')
            ax1.hist(phishing_data, bins=30, alpha=0.7, label='Phishing', color='red')
            ax1.set_xlabel(selected_feature)
            ax1.set_ylabel('Frequency')
            ax1.set_title(f'Distribution of {selected_feature}')
            ax1.legend()
            
            # Box plot
            data_for_box = [legitimate_data, phishing_data]
            ax2.boxplot(data_for_box, labels=['Legitimate', 'Phishing'])
            ax2.set_ylabel(selected_feature)
            ax2.set_title(f'Box Plot of {selected_feature}')
            
            plt.tight_layout()
            st.pyplot(fig)
            
            # Statistics
            st.subheader(f"Statistics for {selected_feature}")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Legitimate URLs:**")
                st.write(f"Mean: {legitimate_data.mean():.3f}")
                st.write(f"Std: {legitimate_data.std():.3f}")
                st.write(f"Min: {legitimate_data.min():.3f}")
                st.write(f"Max: {legitimate_data.max():.3f}")
            
            with col2:
                st.write("**Phishing URLs:**")
                st.write(f"Mean: {phishing_data.mean():.3f}")
                st.write(f"Std: {phishing_data.std():.3f}")
                st.write(f"Min: {phishing_data.min():.3f}")
                st.write(f"Max: {phishing_data.max():.3f}")

if __name__ == "__main__":
    main()
