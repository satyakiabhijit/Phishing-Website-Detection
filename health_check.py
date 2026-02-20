"""
PhishGuard Health Check
Run this script to verify your setup before deployment
"""

import sys
import os
from pathlib import Path

def check_python_version():
    """Check Python version"""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 10:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor} (requires 3.10+)")
        return False

def check_dependencies():
    """Check required packages"""
    print("\n📦 Checking dependencies...")
    required = [
        'pandas', 'numpy', 'sklearn', 'joblib', 'xgboost', 
        'lightgbm', 'streamlit', 'requests', 'dotenv', 'rapidfuzz'
    ]
    missing = []
    for package in required:
        try:
            if package == 'sklearn':
                __import__('sklearn')
            elif package == 'dotenv':
                __import__('dotenv')
            else:
                __import__(package)
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package} (missing)")
            missing.append(package)
    
    if missing:
        print(f"\n   Install missing packages: pip install {' '.join(missing)}")
        return False
    return True

def check_files():
    """Check required files exist"""
    print("\n📁 Checking required files...")
    files = [
        'app.py',
        'training.py',
        'feature_extractor.py',
        'intelligence.py',
        'requirements.txt',
        'alexa_top1k.txt',
    ]
    missing = []
    for file in files:
        if Path(file).exists():
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} (missing)")
            missing.append(file)
    return len(missing) == 0

def check_api_keys():
    """Check API keys configuration"""
    print("\n🔑 Checking API keys...")
    from dotenv import load_dotenv
    load_dotenv()
    
    keys = {
        'VT_API_KEY': 'VirusTotal',
        'GSB_API_KEY': 'Google Safe Browsing',
        'IPQS_API_KEY': 'IPQualityScore'
    }
    
    configured = []
    for key, name in keys.items():
        if os.getenv(key):
            print(f"   ✅ {name}")
            configured.append(name)
        else:
            print(f"   ⚠️  {name} (not configured)")
    
    if len(configured) == 0:
        print("\n   ⚠️  No API keys found. App will work but with limited functionality.")
        print("   Add keys to .env file for full features.")
    elif len(configured) < 3:
        print(f"\n   ℹ️  {len(configured)}/3 APIs configured. Consider adding more for better accuracy.")
    
    return True  # Not critical

def check_models():
    """Check if models are trained"""
    print("\n🤖 Checking ML models...")
    models_dir = Path('models')
    
    if not models_dir.exists():
        print("   ⚠️  Models directory not found")
        print("   Run: python training.py")
        return False
    
    required_models = [
        'random_forest.pkl',
        'gradient_boosting.pkl',
        'xgboost_model.pkl',
        'stacking_classifier.pkl',
        'feature_names.pkl',
        'scaler.pkl'
    ]
    
    missing = []
    for model in required_models:
        if (models_dir / model).exists():
            print(f"   ✅ {model}")
        else:
            print(f"   ❌ {model} (missing)")
            missing.append(model)
    
    if missing:
        print("\n   ⚠️  Some models missing. Run: python training.py")
        return False
    
    return True

def check_dataset():
    """Check if dataset exists"""
    print("\n📊 Checking dataset...")
    
    datasets = ['dataset_phishing.csv', 'data/dataset_phishing_50k.csv']
    found = False
    
    for dataset in datasets:
        if Path(dataset).exists():
            print(f"   ✅ {dataset}")
            found = True
            break
    
    if not found:
        print("   ⚠️  Dataset not found")
        print("   Training will not work without dataset")
        return False
    
    return True

def main():
    """Run all checks"""
    print("=" * 60)
    print("PhishGuard Production Readiness Check")
    print("=" * 60)
    
    checks = [
        ("Python Version", check_python_version()),
        ("Dependencies", check_dependencies()),
        ("Required Files", check_files()),
        ("API Keys", check_api_keys()),
        ("Dataset", check_dataset()),
        ("ML Models", check_models()),
    ]
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in checks if result)
    total = len(checks)
    
    for name, result in checks:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:12} {name}")
    
    print("=" * 60)
    print(f"\n{passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 Your setup is ready for production deployment!")
        print("\nNext steps:")
        print("  1. Test locally: streamlit run app.py")
        print("  2. Deploy to Streamlit Cloud: See DEPLOYMENT.md")
    else:
        print("\n⚠️  Please fix the failed checks before deployment")
        print("\nCommon fixes:")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("  - Train models: python training.py")
        print("  - Add API keys to .env file")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
