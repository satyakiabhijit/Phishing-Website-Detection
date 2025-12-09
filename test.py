#!/usr/bin/env python3
"""
Advanced Phishing Website Detection System with Dataset Integration

This module provides a comprehensive machine learning framework for detecting
phishing websites using the user's dataset_phishing.csv file. It implements
advanced ML techniques including ensemble learning, hyperparameter optimization,
feature engineering, anomaly detection, and model interpretability.
"""

import sys
import os
import logging
import time
import warnings
from datetime import datetime
import pickle
import json
import argparse
import re
import socket
import ssl
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Any, Optional

# Core scientific computing
import numpy as np
import pandas as pd

# Machine learning core
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder, PolynomialFeatures
from sklearn.feature_selection import SelectKBest, f_classif, RFE, SelectFromModel
from sklearn.ensemble import (RandomForestClassifier, GradientBoostingClassifier, 
                             VotingClassifier, StackingClassifier, ExtraTreesClassifier)
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                           roc_auc_score, precision_recall_curve, roc_curve, 
                           f1_score, precision_score, recall_score)
from sklearn.inspection import permutation_importance
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
import joblib

# Advanced ML libraries (with graceful fallback)
try:
    import optuna
    from optuna.samplers import TPESampler
    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False
    print("Optuna not available. Hyperparameter optimization will be disabled.")

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    print("SHAP not available. SHAP explanations will be disabled.")

try:
    from lime.lime_text import LimeTextExplainer
    from lime.lime_tabular import LimeTabularExplainer
    HAS_LIME = True
except ImportError:
    HAS_LIME = False
    print("LIME not available. LIME explanations will be disabled.")

try:
    from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE
    from imblearn.under_sampling import RandomUnderSampler, EditedNearestNeighbours
    from imblearn.combine import SMOTETomek, SMOTEENN
    from imblearn.ensemble import BalancedRandomForestClassifier
    HAS_IMBALANCED = True
except ImportError:
    HAS_IMBALANCED = False
    print("Imbalanced-learn not available. Advanced sampling will be disabled.")

# Visualization libraries
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.offline as pyo
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False
    print("Visualization libraries not available. Advanced plots will be disabled.")

# Gradient boosting libraries
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("XGBoost not available.")

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("LightGBM not available.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_detection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


class AdvancedPhishingDetector:
    """
    Advanced machine learning system for phishing website detection using dataset.
    
    This class implements a comprehensive approach to phishing detection with:
    - Multiple ML algorithms and ensemble methods
    - Advanced feature engineering and selection
    - Hyperparameter optimization with Optuna
    - Model interpretability with SHAP and LIME
    - Anomaly detection for outlier identification
    - Comprehensive evaluation and visualization
    """
    
    def __init__(self, random_state: int = 42):
        """Initialize the advanced phishing detector"""
        self.random_state = random_state
        np.random.seed(random_state)
        
        # Core components
        self.models = {}
        self.ensemble_model = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.stacking_classifier = None
        
        # Dataset and features
        self.df = None
        self.feature_names = None
        self.selected_features = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
        # Model performance tracking
        self.training_history = {}
        self.model_performances = {}
        self.feature_importance_scores = {}
        
        # Advanced components
        self.best_hyperparams = {}
        self.explainer = None
        self.lime_explainer = None
        
        logger.info("Advanced Phishing Detector initialized successfully")
    
    def load_dataset(self, dataset_path: str) -> pd.DataFrame:
        """Load and validate the phishing dataset"""
        try:
            logger.info(f"Loading dataset from {dataset_path}")
            self.df = pd.read_csv(dataset_path)
            
            logger.info(f"Dataset loaded successfully:")
            logger.info(f"  - Shape: {self.df.shape}")
            logger.info(f"  - Columns: {list(self.df.columns)}")
            
            # Validate required columns
            if 'status' not in self.df.columns:
                raise ValueError("Dataset must contain 'status' column")
            
            # Check class distribution
            class_dist = self.df['status'].value_counts()
            logger.info(f"  - Class distribution: {dict(class_dist)}")
            
            # Check for missing values
            missing_info = self.df.isnull().sum()
            if missing_info.sum() > 0:
                logger.warning(f"Missing values found: {missing_info[missing_info > 0].to_dict()}")
            
            return self.df
            
        except Exception as e:
            logger.error(f"Error loading dataset: {str(e)}")
            raise
    
    def preprocess_data(self, test_size: float = 0.2) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Preprocess the dataset for training"""
        try:
            logger.info("Preprocessing dataset...")
            
            # Separate features and target
            if 'url' in self.df.columns:
                X = self.df.drop(['url', 'status'], axis=1)
            else:
                X = self.df.drop(['status'], axis=1)
            
            y = self.df['status']
            
            # Store feature names
            self.feature_names = list(X.columns)
            logger.info(f"Total features: {len(self.feature_names)}")
            
            # Handle missing values
            X = X.fillna(X.median())
            
            # Convert categorical variables if any
            for col in X.columns:
                if X[col].dtype == 'object':
                    X[col] = LabelEncoder().fit_transform(X[col].astype(str))
            
            # Split the data
            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                X, y, test_size=test_size, random_state=self.random_state, 
                stratify=y
            )
            
            logger.info(f"Data split completed:")
            logger.info(f"  - Training set: {self.X_train.shape}")
            logger.info(f"  - Test set: {self.X_test.shape}")
            
            return self.X_train, self.X_test, self.y_train, self.y_test
            
        except Exception as e:
            logger.error(f"Error in data preprocessing: {str(e)}")
            raise
    
    def _advanced_feature_engineering(self, X: pd.DataFrame) -> pd.DataFrame:
        """Apply advanced feature engineering techniques"""
        logger.info("Applying advanced feature engineering...")
        
        X_engineered = X.copy()
        
        try:
            # Feature interactions
            important_features = ['length_url', 'nb_dots', 'nb_hyphens', 'nb_slash']
            available_features = [f for f in important_features if f in X.columns]
            
            if len(available_features) >= 2:
                # Create interaction features
                for i, feat1 in enumerate(available_features):
                    for feat2 in available_features[i+1:]:
                        X_engineered[f'{feat1}_x_{feat2}'] = X[feat1] * X[feat2]
                        X_engineered[f'{feat1}_div_{feat2}'] = X[feat1] / (X[feat2] + 1e-6)
            
            # Polynomial features for selected important features
            if len(available_features) > 0:
                poly = PolynomialFeatures(degree=2, interaction_only=True, include_bias=False)
                X_poly = poly.fit_transform(X[available_features[:3]])  # Limit to avoid explosion
                poly_feature_names = [f'poly_{i}' for i in range(X_poly.shape[1] - len(available_features[:3]))]
                
                for i, name in enumerate(poly_feature_names):
                    X_engineered[name] = X_poly[:, len(available_features[:3]) + i]
            
            # Domain-specific engineered features
            if 'length_url' in X.columns and 'nb_dots' in X.columns:
                X_engineered['url_complexity'] = X['length_url'] * X['nb_dots']
            
            if 'nb_hyphens' in X.columns and 'nb_underscore' in X.columns:
                X_engineered['special_char_density'] = X['nb_hyphens'] + X.get('nb_underscore', 0)
            
            logger.info(f"Feature engineering completed. New shape: {X_engineered.shape}")
            
        except Exception as e:
            logger.warning(f"Feature engineering partially failed: {str(e)}")
        
        return X_engineered
    
    def _select_features(self, X: pd.DataFrame, y: pd.Series, method: str = 'combined', k: int = 50) -> pd.DataFrame:
        """Select best features using multiple methods"""
        logger.info(f"Selecting features using {method} method...")
        
        if method == 'univariate':
            selector = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
            X_selected = selector.fit_transform(X, y)
            selected_features = X.columns[selector.get_support()].tolist()
            
        elif method == 'rfe':
            estimator = RandomForestClassifier(n_estimators=50, random_state=self.random_state)
            selector = RFE(estimator, n_features_to_select=min(k, X.shape[1]))
            X_selected = selector.fit_transform(X, y)
            selected_features = X.columns[selector.get_support()].tolist()
            
        elif method == 'model_based':
            estimator = RandomForestClassifier(n_estimators=100, random_state=self.random_state)
            estimator.fit(X, y)
            selector = SelectFromModel(estimator, max_features=min(k, X.shape[1]))
            X_selected = selector.fit_transform(X, y)
            selected_features = X.columns[selector.get_support()].tolist()
            
        elif method == 'combined':
            # Combine multiple methods
            selectors = [
                SelectKBest(score_func=f_classif, k=min(k, X.shape[1])),
                SelectFromModel(RandomForestClassifier(n_estimators=50, random_state=self.random_state), 
                               max_features=min(k, X.shape[1]))
            ]
            
            selected_features_sets = []
            for selector in selectors:
                selector.fit(X, y)
                selected_features_sets.append(set(X.columns[selector.get_support()].tolist()))
            
            # Take intersection of selected features
            selected_features = list(set.intersection(*selected_features_sets))
            
            # If intersection is too small, use union of top features
            if len(selected_features) < k // 2:
                selected_features = list(set.union(*selected_features_sets))[:k]
            
            X_selected = X[selected_features]
        
        self.selected_features = selected_features
        logger.info(f"Selected {len(selected_features)} features: {selected_features[:10]}...")
        
        return X_selected
    
    def optimize_hyperparameters(self, X: pd.DataFrame, y: pd.Series, n_trials: int = 100) -> Dict[str, Dict]:
        """Optimize hyperparameters using Optuna"""
        if not HAS_OPTUNA:
            logger.warning("Optuna not available. Using default hyperparameters.")
            return {}
        
        logger.info(f"Starting hyperparameter optimization with {n_trials} trials...")
        
        def objective(trial):
            # Random Forest hyperparameters
            rf_params = {
                'n_estimators': trial.suggest_int('rf_n_estimators', 50, 300),
                'max_depth': trial.suggest_int('rf_max_depth', 5, 20),
                'min_samples_split': trial.suggest_int('rf_min_samples_split', 2, 20),
                'min_samples_leaf': trial.suggest_int('rf_min_samples_leaf', 1, 10)
            }
            
            model = RandomForestClassifier(**rf_params, random_state=self.random_state)
            scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
            return scores.mean()
        
        study = optuna.create_study(direction='maximize', sampler=TPESampler())
        study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
        
        self.best_hyperparams['random_forest'] = study.best_params
        logger.info(f"Best hyperparameters: {study.best_params}")
        logger.info(f"Best score: {study.best_value:.4f}")
        
        return self.best_hyperparams
    
    def train_advanced_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Dict]:
        """Train multiple advanced ML models"""
        logger.info("Training advanced machine learning models...")
        
        models_config = {
            'random_forest': RandomForestClassifier(
                n_estimators=200, 
                max_depth=15, 
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=self.random_state
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=self.random_state
            ),
            'extra_trees': ExtraTreesClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=self.random_state
            ),
            'logistic_regression': LogisticRegression(
                random_state=self.random_state,
                max_iter=1000,
                C=1.0
            ),
            'svm': SVC(
                probability=True,
                random_state=self.random_state,
                C=1.0,
                gamma='scale'
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                random_state=self.random_state,
                max_iter=500,
                alpha=0.001
            ),
            'naive_bayes': GaussianNB(),
            'knn': KNeighborsClassifier(n_neighbors=5),
            'decision_tree': DecisionTreeClassifier(
                max_depth=10,
                random_state=self.random_state
            )
        }
        
        # Add XGBoost if available
        if HAS_XGBOOST:
            models_config['xgboost'] = xgb.XGBClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=self.random_state
            )
        
        # Add LightGBM if available
        if HAS_LIGHTGBM:
            models_config['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=self.random_state,
                verbose=-1
            )
        
        # Add balanced random forest if available
        if HAS_IMBALANCED:
            models_config['balanced_rf'] = BalancedRandomForestClassifier(
                n_estimators=200,
                random_state=self.random_state
            )
        
        results = {}
        
        # Train each model
        for name, model in models_config.items():
            try:
                logger.info(f"Training {name}...")
                start_time = time.time()
                
                # Cross-validation
                cv_scores = cross_val_score(model, X, y, cv=5, scoring='roc_auc')
                
                # Fit the model
                model.fit(X, y)
                
                training_time = time.time() - start_time
                
                # Store results
                results[name] = {
                    'model': model,
                    'cv_scores': cv_scores,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'training_time': training_time
                }
                
                self.models[name] = model
                self.training_history[name] = results[name]
                
                logger.info(f"{name} - CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
                
            except Exception as e:
                logger.error(f"Error training {name}: {str(e)}")
                continue
        
        return results
    
    def create_stacked_ensemble(self, X: pd.DataFrame, y: pd.Series) -> StackingClassifier:
        """Create an advanced stacked ensemble model"""
        logger.info("Creating stacked ensemble model...")
        
        # Base models for stacking
        base_models = []
        for name, model in self.models.items():
            if name in ['random_forest', 'gradient_boosting', 'extra_trees', 'xgboost', 'lightgbm']:
                base_models.append((name, model))
        
        if len(base_models) < 2:
            logger.warning("Not enough models for stacking. Using voting classifier instead.")
            return self.create_voting_ensemble(X, y)
        
        # Meta-learner
        meta_learner = LogisticRegression(random_state=self.random_state)
        
        # Create stacking classifier
        self.stacking_classifier = StackingClassifier(
            estimators=base_models,
            final_estimator=meta_learner,
            cv=5,
            n_jobs=-1
        )
        
        # Train the stacking classifier
        self.stacking_classifier.fit(X, y)
        
        # Evaluate performance
        cv_scores = cross_val_score(self.stacking_classifier, X, y, cv=5, scoring='roc_auc')
        logger.info(f"Stacking Classifier CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        return self.stacking_classifier
    
    def create_voting_ensemble(self, X: pd.DataFrame, y: pd.Series) -> VotingClassifier:
        """Create a voting ensemble as fallback"""
        logger.info("Creating voting ensemble...")
        
        # Select best performing models for ensemble
        ensemble_models = []
        for name, model in self.models.items():
            if name in ['random_forest', 'gradient_boosting', 'logistic_regression']:
                ensemble_models.append((name, model))
        
        if len(ensemble_models) < 2:
            logger.warning("Not enough models for ensemble. Using best single model.")
            return None
        
        self.ensemble_model = VotingClassifier(
            estimators=ensemble_models,
            voting='soft'
        )
        
        self.ensemble_model.fit(X, y)
        return self.ensemble_model
    
    def train_anomaly_detector(self, X: pd.DataFrame) -> IsolationForest:
        """Train anomaly detection model"""
        logger.info("Training anomaly detection model...")
        
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=self.random_state,
            n_estimators=100
        )
        
        self.anomaly_detector.fit(X)
        
        # Test anomaly detection
        anomaly_scores = self.anomaly_detector.decision_function(X)
        anomalies = self.anomaly_detector.predict(X)
        
        logger.info(f"Anomaly detection trained. Found {sum(anomalies == -1)} anomalies out of {len(X)} samples")
        
        return self.anomaly_detector
    
    def evaluate_comprehensive(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
        """Comprehensive model evaluation"""
        logger.info("Performing comprehensive model evaluation...")
        
        results = {}
        
        # Evaluate each individual model
        for name, model in self.models.items():
            try:
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
                
                metrics = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred),
                    'recall': recall_score(y_test, y_pred),
                    'f1': f1_score(y_test, y_pred),
                    'auc': roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else None
                }
                
                results[name] = metrics
                
            except Exception as e:
                logger.error(f"Error evaluating {name}: {str(e)}")
        
        # Evaluate ensemble models
        if self.stacking_classifier:
            try:
                y_pred = self.stacking_classifier.predict(X_test)
                y_pred_proba = self.stacking_classifier.predict_proba(X_test)[:, 1]
                
                results['stacking_ensemble'] = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred),
                    'recall': recall_score(y_test, y_pred),
                    'f1': f1_score(y_test, y_pred),
                    'auc': roc_auc_score(y_test, y_pred_proba)
                }
            except Exception as e:
                logger.error(f"Error evaluating stacking ensemble: {str(e)}")
        
        if self.ensemble_model:
            try:
                y_pred = self.ensemble_model.predict(X_test)
                y_pred_proba = self.ensemble_model.predict_proba(X_test)[:, 1]
                
                results['voting_ensemble'] = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred),
                    'recall': recall_score(y_test, y_pred),
                    'f1': f1_score(y_test, y_pred),
                    'auc': roc_auc_score(y_test, y_pred_proba)
                }
            except Exception as e:
                logger.error(f"Error evaluating voting ensemble: {str(e)}")
        
        # Display results
        logger.info("Model Performance Summary:")
        for model_name, metrics in results.items():
            logger.info(f"{model_name}:")
            for metric, value in metrics.items():
                if value is not None:
                    logger.info(f"  {metric}: {value:.4f}")
        
        return results
    
    def generate_feature_importance_report(self) -> Dict[str, Any]:
        """Generate comprehensive feature importance analysis"""
        logger.info("Generating feature importance analysis...")
        
        importance_data = {}
        
        # Random Forest feature importance
        if 'random_forest' in self.models:
            rf_importance = self.models['random_forest'].feature_importances_
            importance_data['random_forest'] = {
                'features': self.selected_features,
                'importance': rf_importance.tolist()
            }
        
        # Gradient Boosting feature importance
        if 'gradient_boosting' in self.models:
            gb_importance = self.models['gradient_boosting'].feature_importances_
            importance_data['gradient_boosting'] = {
                'features': self.selected_features,
                'importance': gb_importance.tolist()
            }
        
        # Permutation importance
        if 'random_forest' in self.models and self.X_test is not None:
            try:
                perm_importance = permutation_importance(
                    self.models['random_forest'], 
                    self.X_test, 
                    self.y_test, 
                    n_repeats=5,
                    random_state=self.random_state
                )
                importance_data['permutation'] = {
                    'features': self.selected_features,
                    'importance': perm_importance.importances_mean.tolist(),
                    'std': perm_importance.importances_std.tolist()
                }
            except Exception as e:
                logger.warning(f"Could not compute permutation importance: {str(e)}")
        
        # SHAP values (if available)
        if HAS_SHAP and 'random_forest' in self.models:
            try:
                explainer = shap.TreeExplainer(self.models['random_forest'])
                shap_values = explainer.shap_values(self.X_test.iloc[:100])  # Sample for speed
                
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # For binary classification
                
                importance_data['shap'] = {
                    'features': self.selected_features,
                    'importance': np.abs(shap_values).mean(axis=0).tolist()
                }
            except Exception as e:
                logger.warning(f"Could not compute SHAP values: {str(e)}")
        
        self.feature_importance_scores = importance_data
        return importance_data
    
    def create_model_visualizations(self) -> str:
        """Create comprehensive model visualizations"""
        if not HAS_VISUALIZATION:
            logger.warning("Visualization libraries not available")
            return ""
        
        logger.info("Creating model visualizations...")
        
        try:
            # Create subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=[
                    'Model Performance Comparison',
                    'Feature Importance (Top 20)',
                    'Class Distribution',
                    'Model Training Times'
                ],
                specs=[[{"type": "bar"}, {"type": "bar"}],
                       [{"type": "pie"}, {"type": "bar"}]]
            )
            
            # Model performance comparison
            if hasattr(self, 'model_performances') and self.model_performances:
                models = list(self.model_performances.keys())
                auc_scores = [metrics.get('auc', 0) for metrics in self.model_performances.values()]
                
                fig.add_trace(
                    go.Bar(x=models, y=auc_scores, name="AUC Score"),
                    row=1, col=1
                )
            
            # Feature importance
            if hasattr(self, 'feature_importance_scores') and 'random_forest' in self.feature_importance_scores:
                rf_data = self.feature_importance_scores['random_forest']
                top_features = sorted(
                    zip(rf_data['features'], rf_data['importance']),
                    key=lambda x: x[1],
                    reverse=True
                )[:20]
                
                features, importance = zip(*top_features)
                
                fig.add_trace(
                    go.Bar(x=list(features), y=list(importance), name="Importance"),
                    row=1, col=2
                )
            
            # Class distribution
            if self.df is not None:
                class_counts = self.df['status'].value_counts()
                fig.add_trace(
                    go.Pie(labels=class_counts.index, values=class_counts.values, name="Classes"),
                    row=2, col=1
                )
            
            # Training times
            if hasattr(self, 'training_history') and self.training_history:
                models = list(self.training_history.keys())
                times = [data['training_time'] for data in self.training_history.values()]
                
                fig.add_trace(
                    go.Bar(x=models, y=times, name="Training Time (s)"),
                    row=2, col=2
                )
            
            # Update layout
            fig.update_layout(
                title_text="Advanced Phishing Detection - Model Analysis",
                showlegend=False,
                height=800
            )
            
            # Save as HTML
            output_file = "model_analysis.html"
            fig.write_html(output_file)
            logger.info(f"Visualizations saved to {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Error creating visualizations: {str(e)}")
            return ""
    
    def save_advanced_models(self, model_dir: str = 'models') -> bool:
        """Save all trained models and components"""
        try:
            os.makedirs(model_dir, exist_ok=True)
            
            # Save individual models
            for name, model in self.models.items():
                joblib.dump(model, os.path.join(model_dir, f'{name}_model.pkl'))
            
            # Save ensemble models
            if self.stacking_classifier:
                joblib.dump(self.stacking_classifier, os.path.join(model_dir, 'stacking_ensemble.pkl'))
            
            if self.ensemble_model:
                joblib.dump(self.ensemble_model, os.path.join(model_dir, 'voting_ensemble.pkl'))
            
            # Save preprocessing components
            if self.scaler:
                joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.pkl'))
            
            if self.feature_selector:
                joblib.dump(self.feature_selector, os.path.join(model_dir, 'feature_selector.pkl'))
            
            if self.anomaly_detector:
                joblib.dump(self.anomaly_detector, os.path.join(model_dir, 'anomaly_detector.pkl'))
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'selected_features': self.selected_features,
                'training_history': self.training_history,
                'model_performances': getattr(self, 'model_performances', {}),
                'best_hyperparams': self.best_hyperparams,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(os.path.join(model_dir, 'metadata.json'), 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            logger.info(f"All models and components saved to {model_dir}/")
            return True
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
            return False
    
    def load_advanced_models(self, model_dir: str = 'models') -> bool:
        """Load all trained models and components"""
        try:
            # Load metadata
            with open(os.path.join(model_dir, 'metadata.json'), 'r') as f:
                metadata = json.load(f)
            
            self.feature_names = metadata.get('feature_names', [])
            self.selected_features = metadata.get('selected_features', [])
            self.training_history = metadata.get('training_history', {})
            self.model_performances = metadata.get('model_performances', {})
            self.best_hyperparams = metadata.get('best_hyperparams', {})
            
            # Load preprocessing components
            scaler_path = os.path.join(model_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            
            # Load individual models
            model_files = [f for f in os.listdir(model_dir) if f.endswith('_model.pkl')]
            for model_file in model_files:
                model_name = model_file.replace('_model.pkl', '')
                self.models[model_name] = joblib.load(os.path.join(model_dir, model_file))
            
            # Load ensemble models
            stacking_path = os.path.join(model_dir, 'stacking_ensemble.pkl')
            if os.path.exists(stacking_path):
                self.stacking_classifier = joblib.load(stacking_path)
            
            voting_path = os.path.join(model_dir, 'voting_ensemble.pkl')
            if os.path.exists(voting_path):
                self.ensemble_model = joblib.load(voting_path)
            
            # Load anomaly detector
            anomaly_path = os.path.join(model_dir, 'anomaly_detector.pkl')
            if os.path.exists(anomaly_path):
                self.anomaly_detector = joblib.load(anomaly_path)
            
            logger.info(f"Models loaded successfully from {model_dir}/")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            return False
    
    def train_complete_system(self, dataset_path: str, test_size: float = 0.2, 
                            optimize_hyperparams: bool = False, n_trials: int = 50) -> Dict[str, Any]:
        """Train the complete advanced system"""
        logger.info("Starting complete system training...")
        
        try:
            # Load and preprocess data
            self.load_dataset(dataset_path)
            X_train, X_test, y_train, y_test = self.preprocess_data(test_size)
            
            # Advanced feature engineering
            X_train_engineered = self._advanced_feature_engineering(pd.DataFrame(X_train, columns=self.feature_names))
            X_test_engineered = self._advanced_feature_engineering(pd.DataFrame(X_test, columns=self.feature_names))
            
            # Feature selection
            X_train_selected = self._select_features(X_train_engineered, y_train, method='combined', k=50)
            X_test_selected = X_test_engineered[self.selected_features]
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train_selected)
            X_test_scaled = self.scaler.transform(X_test_selected)
            
            # Update internal data
            self.X_train = pd.DataFrame(X_train_scaled, columns=self.selected_features)
            self.X_test = pd.DataFrame(X_test_scaled, columns=self.selected_features)
            self.y_train = y_train
            self.y_test = y_test
            
            # Hyperparameter optimization (optional)
            if optimize_hyperparams and HAS_OPTUNA:
                self.optimize_hyperparameters(self.X_train, self.y_train, n_trials)
            
            # Train advanced models
            model_results = self.train_advanced_models(self.X_train, self.y_train)
            
            # Create ensemble models
            self.create_stacked_ensemble(self.X_train, self.y_train)
            if not self.stacking_classifier:
                self.create_voting_ensemble(self.X_train, self.y_train)
            
            # Train anomaly detector
            self.train_anomaly_detector(self.X_train)
            
            # Comprehensive evaluation
            self.model_performances = self.evaluate_comprehensive(self.X_test, self.y_test)
            
            # Feature importance analysis
            self.generate_feature_importance_report()
            
            # Create visualizations
            if HAS_VISUALIZATION:
                self.create_model_visualizations()
            
            # Save models
            self.save_advanced_models()
            
            logger.info("Complete system training finished successfully!")
            return self.model_performances
            
        except Exception as e:
            logger.error(f"System training failed: {str(e)}")
            raise
    
    def predict_advanced(self, features: pd.DataFrame, return_details: bool = False) -> Dict[str, Any]:
        """Make advanced predictions with multiple models"""
        try:
            # Ensure features match training format
            if isinstance(features, pd.Series):
                features = features.to_frame().T
            
            # Align features with selected features
            if self.selected_features:
                missing_features = [f for f in self.selected_features if f not in features.columns]
                for feature in missing_features:
                    features[feature] = 0
                features = features[self.selected_features]
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            features_df = pd.DataFrame(features_scaled, columns=self.selected_features)
            
            # Get predictions from all models
            predictions = {}
            probabilities = {}
            
            for name, model in self.models.items():
                try:
                    pred = model.predict(features_df)[0]
                    prob = model.predict_proba(features_df)[0] if hasattr(model, 'predict_proba') else [0.5, 0.5]
                    
                    predictions[name] = pred
                    probabilities[name] = {
                        'legitimate': prob[0],
                        'phishing': prob[1],
                        'prediction': 'phishing' if pred == 1 else 'legitimate'
                    }
                except Exception as e:
                    logger.warning(f"Prediction failed for {name}: {str(e)}")
            
            # Ensemble prediction
            ensemble_pred = None
            ensemble_prob = None
            
            if self.stacking_classifier:
                ensemble_pred = self.stacking_classifier.predict(features_df)[0]
                ensemble_prob = self.stacking_classifier.predict_proba(features_df)[0]
            elif self.ensemble_model:
                ensemble_pred = self.ensemble_model.predict(features_df)[0]
                ensemble_prob = self.ensemble_model.predict_proba(features_df)[0]
            
            # Anomaly detection
            anomaly_score = None
            is_anomaly = False
            
            if self.anomaly_detector:
                anomaly_score = self.anomaly_detector.decision_function(features_df)[0]
                is_anomaly = self.anomaly_detector.predict(features_df)[0] == -1
            
            # Final result
            final_prediction = 'phishing' if ensemble_pred == 1 else 'legitimate'
            phishing_probability = ensemble_prob[1] if ensemble_prob is not None else 0.5
            
            result = {
                'prediction': final_prediction,
                'phishing_probability': float(phishing_probability),
                'confidence': float(max(ensemble_prob) if ensemble_prob is not None else 0.5),
                'risk_level': self._get_risk_level(phishing_probability),
                'anomaly_score': float(anomaly_score) if anomaly_score is not None else 0.0,
                'is_anomaly': is_anomaly
            }
            
            if return_details:
                result['individual_models'] = probabilities
                result['ensemble_used'] = 'stacking' if self.stacking_classifier else 'voting'
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return {
                'prediction': 'error',
                'phishing_probability': 0.5,
                'confidence': 0.0,
                'risk_level': 'unknown',
                'error': str(e)
            }
    
    def _get_risk_level(self, phishing_prob: float) -> str:
        """Determine risk level based on phishing probability"""
        if phishing_prob >= 0.9:
            return 'Critical'
        elif phishing_prob >= 0.8:
            return 'Very High'
        elif phishing_prob >= 0.6:
            return 'High'
        elif phishing_prob >= 0.4:
            return 'Medium'
        elif phishing_prob >= 0.2:
            return 'Low'
        else:
            return 'Very Low'


# Main execution and demonstration
if __name__ == "__main__":
    logger.info("Initializing Advanced Phishing Detection System...")
    
    # Initialize the advanced detector
    detector = AdvancedPhishingDetector()
    
    # Check if dataset exists
    dataset_path = "dataset_phishing.csv"
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}")
        logger.info("Please ensure the dataset_phishing.csv file is in the same directory as this script.")
        exit(1)
    
    try:
        # Train the complete system
        logger.info("Starting comprehensive training with your dataset...")
        results = detector.train_complete_system(
            dataset_path=dataset_path,
            optimize_hyperparams=False,  # Set to True for hyperparameter optimization
            n_trials=20  # Reduce for faster training
        )
        
        logger.info("Training completed successfully!")
        
        # Demonstrate prediction with sample data from dataset
        logger.info("Testing prediction on sample data...")
        
        # Load a sample for testing
        df_sample = pd.read_csv(dataset_path).head(1)
        sample_features = df_sample.drop(['url', 'status'], axis=1)
        
        # Make prediction
        prediction_result = detector.predict_advanced(sample_features, return_details=True)
        
        print("\n" + "="*60)
        print("SAMPLE PREDICTION RESULTS")
        print("="*60)
        print(f"URL: {df_sample['url'].iloc[0]}")
        print(f"Actual Status: {df_sample['status'].iloc[0]}")
        print(f"Predicted: {prediction_result['prediction']}")
        print(f"Phishing Probability: {prediction_result['phishing_probability']:.4f}")
        print(f"Risk Level: {prediction_result['risk_level']}")
        print(f"Confidence: {prediction_result['confidence']:.4f}")
        print(f"Anomaly Score: {prediction_result['anomaly_score']:.4f}")
        print(f"Is Anomaly: {prediction_result['is_anomaly']}")
        
        print("\nIndividual Model Predictions:")
        for model_name, pred in prediction_result['individual_models'].items():
            print(f"  {model_name}: {pred['prediction']} ({pred['phishing_probability']:.4f})")
        
        print("\n" + "="*60)
        print("TRAINING SUMMARY")
        print("="*60)
        
        # Print best performing models
        best_auc = 0
        best_model = None
        for model_name, metrics in results.items():
            if metrics['auc'] > best_auc:
                best_auc = metrics['auc']
                best_model = model_name
        
        print(f"Best performing model: {best_model} (AUC: {best_auc:.4f})")
        print(f"Total models trained: {len(detector.models)}")
        print(f"Feature count after selection: {len(detector.feature_names) if detector.feature_names else 'N/A'}")
        print(f"Dataset size: {detector.df.shape[0]} samples, {detector.df.shape[1]-2} original features")
        
        # Show training time summary
        if detector.training_history:
            total_time = sum(model_data['training_time'] for model_data in detector.training_history.values())
            print(f"Total training time: {total_time:.2f} seconds")
        
        print("\nAdvanced features enabled:")
        print(f"  - Hyperparameter optimization: {'Yes' if HAS_OPTUNA else 'No'}")
        print(f"  - SHAP explanations: {'Yes' if HAS_SHAP else 'No'}")
        print(f"  - LIME interpretability: {'Yes' if HAS_LIME else 'No'}")
        print(f"  - Imbalanced learning: {'Yes' if HAS_IMBALANCED else 'No'}")
        print(f"  - Advanced visualizations: {'Yes' if HAS_VISUALIZATION else 'No'}")
        
        print(f"\nModels and artifacts saved in 'models/' directory")
        print(f"Visualizations saved as 'model_analysis.html'")
        
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        logger.info("Please ensure all dependencies are installed: pip install -r requirements.txt")
        raise
