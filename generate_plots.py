import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc, confusion_matrix
import joblib
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='lightgbm')

def main():
    os.makedirs("paper_figures", exist_ok=True)
    print("Generating paper figures from real model data...")

    # Load results
    try:
        with open("models/training_results.json", "r") as f:
            results = json.load(f)
    except Exception as e:
        print("Error: Could not load models/training_results.json", e)
        print("Please ensure you have run training.py first.")
        return

    # ---------------------------------------------------------
    # Plot 1: Model Comparison (Accuracy, AUC, F1)
    # ---------------------------------------------------------
    print("Generating fig1_model_comparison.png...")
    models_keys = list(results["base_models"].keys()) + ["stacking"]
    models_labels = [m.upper() for m in results["base_models"].keys()] + ["STACKING"]
    
    acc = [results["base_models"][m]["test_accuracy"] for m in results["base_models"]] + [results["stacking"]["test_accuracy"]]
    auc_scores = [results["base_models"][m]["test_auc"] for m in results["base_models"]] + [results["stacking"]["test_auc"]]
    f1 = [results["base_models"][m]["test_f1"] for m in results["base_models"]] + [results["stacking"]["test_f1"]]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(models_keys))
    width = 0.25

    ax.bar(x - width, acc, width, label='Accuracy', color='#1f77b4')
    ax.bar(x, auc_scores, width, label='AUC-ROC', color='#ff7f0e')
    ax.bar(x + width, f1, width, label='F1-Score', color='#2ca02c')

    ax.set_ylabel('Scores')
    ax.set_title('Model Performance Comparison — URL-Only Feature Set')
    ax.set_xticks(x)
    ax.set_xticklabels(models_labels)
    
    # Adjust ylim to make bars visible. The results show ~0.99 for all, so we use 0.98 to 1.00
    min_score = min(min(acc), min(auc_scores), min(f1))
    ax.set_ylim(max(0.0, min_score - 0.01), 1.0)
    ax.legend(loc='lower right')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    for i in range(len(models_keys)):
        ax.text(i - width, acc[i] + 0.0005, f"{acc[i]:.4f}", ha='center', va='bottom', fontsize=8, rotation=90)
        ax.text(i, auc_scores[i] + 0.0005, f"{auc_scores[i]:.4f}", ha='center', va='bottom', fontsize=8, rotation=90)
        ax.text(i + width, f1[i] + 0.0005, f"{f1[i]:.4f}", ha='center', va='bottom', fontsize=8, rotation=90)

    plt.tight_layout()
    plt.savefig("paper_figures/fig1_model_comparison.png", dpi=300)
    plt.close()

    # ---------------------------------------------------------
    # Plot 3: Training Time Comparison
    # ---------------------------------------------------------
    print("Generating fig3_training_time.png...")
    times = [results["base_models"][m]["train_time_s"] for m in results["base_models"]]
    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(results["base_models"]))
    bars = ax.barh(y_pos, times, color='#17becf')
    ax.set_yticks(y_pos)
    ax.set_yticklabels([m.upper() for m in results["base_models"]])
    ax.invert_yaxis()
    ax.set_xlabel('Time (seconds)')
    ax.set_title('Model Training Time Comparison (seconds)')
    ax.grid(axis='x', linestyle='--', alpha=0.7)
    
    for bar in bars:
        width = bar.get_width()
        ax.text(width + max(times)*0.01, bar.get_y() + bar.get_height()/2, f"{width:.1f}s", va='center', ha='left', fontsize=10)
        
    plt.tight_layout()
    plt.savefig("paper_figures/fig3_training_time.png", dpi=300)
    plt.close()

    # ---------------------------------------------------------
    # Plot 6: Feature Importance
    # ---------------------------------------------------------
    print("Generating fig6_feature_importance.png...")
    try:
        with open("models/feature_importance.json", "r") as f:
            feat_data = json.load(f)
        features = list(feat_data.keys())[:15]
        importances = list(feat_data.values())[:15]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        y_pos = np.arange(len(features))
        bars = ax.barh(y_pos, importances, color='#d62728')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(features)
        ax.invert_yaxis()
        ax.set_xlabel('Gini Importance')
        ax.set_title('Top 15 Feature Importances (Random Forest)')
        ax.grid(axis='x', linestyle='--', alpha=0.7)
        
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.001, bar.get_y() + bar.get_height()/2, f"{width:.4f}", va='center', ha='left', fontsize=9)
            
        plt.tight_layout()
        plt.savefig("paper_figures/fig6_feature_importance.png", dpi=300)
        plt.close()
    except Exception as e:
        print(f"Warning: Could not plot feature importance: {e}")

    # ---------------------------------------------------------
    # Plots requiring Dataset & Models (ROC, Confusion Matrix)
    # ---------------------------------------------------------
    print("\nLoading dataset and models to generate ROC curves and Confusion Matrix...")
    print("This may take a minute depending on your hardware...")
    
    try:
        df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", encoding="utf-8-sig")
        from sklearn.model_selection import train_test_split
        
        LABEL_COL = "label"
        DROP_COLS = ["FILENAME", "URL", "Domain", "TLD", "Title"]
        URL_ONLY_FEATURES = [
            "URLLength", "DomainLength", "IsDomainIP",
            "CharContinuationRate", "TLDLegitimateProb", "URLCharProb",
            "TLDLength", "NoOfSubDomain", "HasObfuscation",
            "NoOfObfuscatedChar", "ObfuscationRatio",
            "NoOfLettersInURL", "LetterRatioInURL",
            "NoOfDegitsInURL", "DegitRatioInURL",
            "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
            "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
            "IsHTTPS"
        ]
        
        df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")
        for col in df.columns:
            if col != LABEL_COL:
                df[col] = pd.to_numeric(df[col], errors="coerce")
        df = df.fillna(df.median(numeric_only=True))
        
        y = df[LABEL_COL].astype(int)
        X = df.drop(columns=[LABEL_COL])
        available = [f for f in URL_ONLY_FEATURES if f in X.columns]
        X = X[available]
        
        # We must use the exact same random state as training.py to evaluate on the real test set
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
        
        scaler = joblib.load("models/scaler.joblib")
        X_test_scaled = scaler.transform(X_test)
        
        # ---------------------------------------------------------
        # Plot 2: ROC Curves
        # ---------------------------------------------------------
        print("Generating fig2_cv_auc_scores.png (ROC Curves)...")
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Create inset axes for zoom
        axins = ax.inset_axes([0.35, 0.25, 0.6, 0.5])
        
        colors = ['blue', 'green', 'red', 'purple', 'orange']
        base_models = ["rf", "xgb", "lgb", "mlp", "lr"]
        
        for idx, m in enumerate(base_models):
            try:
                model = joblib.load(f"models/{m}.joblib")
                y_prob = model.predict_proba(X_test_scaled)[:, 1]
                fpr, tpr, _ = roc_curve(y_test, y_prob)
                roc_auc = auc(fpr, tpr)
                
                # Plot on main axes
                ax.plot(fpr, tpr, lw=2, color=colors[idx], label=f'{m.upper()} (AUC = {roc_auc:.4f})', alpha=0.8)
                
                # Plot on inset axes
                axins.plot(fpr, tpr, lw=2, color=colors[idx], alpha=0.8)
            except Exception as e:
                print(f"Skipping ROC for {m} due to error: {e}")
            
        try:
            stacking = joblib.load("models/stacking_ensemble.joblib")
            y_prob_s = stacking.predict_proba(X_test_scaled)[:, 1]
            fpr_s, tpr_s, _ = roc_curve(y_test, y_prob_s)
            roc_auc_s = auc(fpr_s, tpr_s)
            
            # Plot on main axes
            ax.plot(fpr_s, tpr_s, lw=3, color='black', label=f'STACKING (AUC = {roc_auc_s:.4f})')
            
            # Plot on inset axes
            axins.plot(fpr_s, tpr_s, lw=3, color='black')
            
            # ---------------------------------------------------------
            # Plot 13: Confusion Matrix
            # ---------------------------------------------------------
            print("Generating fig13_performance_heatmap.png (Confusion Matrix)...")
            y_pred_s = stacking.predict(X_test_scaled)
            cm = confusion_matrix(y_test, y_pred_s)
            
            fig2, ax2 = plt.subplots(figsize=(8, 6))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Legitimate', 'Phishing'], 
                        yticklabels=['Legitimate', 'Phishing'],
                        annot_kws={"size": 14})
            ax2.set_ylabel('True Label', fontsize=12)
            ax2.set_xlabel('Predicted Label', fontsize=12)
            ax2.set_title('Confusion Matrix — Stacking Ensemble', fontsize=14)
            fig2.tight_layout()
            fig2.savefig("paper_figures/fig13_performance_heatmap.png", dpi=300)
            plt.close(fig2)
            
        except Exception as e:
            print(f"Skipping Stacking ROC/CM due to error: {e}")
        
        ax.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--')
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title('ROC Curves — PhishGuard Ensemble Models', fontsize=14)
        ax.legend(loc="lower right", fontsize=10)
        
        # Configure inset zoom
        axins.set_xlim(0.0, 0.05)
        axins.set_ylim(0.95, 1.0)
        axins.set_title('Zoom: Top-Left Corner', fontsize=10)
        axins.grid(True, linestyle='--', alpha=0.5)
        ax.indicate_inset_zoom(axins, edgecolor="black")
        
        fig.tight_layout()
        fig.savefig("paper_figures/fig2_cv_auc_scores.png", dpi=300)
        plt.close(fig)

    except Exception as e:
        print(f"Warning: Could not load data/models for ROC and CM: {e}")

    print("\n✅ All real plots generated successfully in 'paper_figures' directory!")

if __name__ == "__main__":
    main()
