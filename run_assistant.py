#!/usr/bin/env python3
"""
Simple launcher script for the Security Incident Triage Assistant
"""

import subprocess
import sys
import os
from pathlib import Path

def check_requirements():
    """Check if required dependencies are installed"""
    try:
        import openai
        import dotenv
        return True
    except ImportError as e:
        print(f"❌ Missing required dependency: {e}")
        print("📦 Installing requirements...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("✅ Requirements installed successfully!")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install requirements. Please run: pip install -r requirements.txt")
            return False

def check_env_file():
    """Check if .env file exists and has required variables"""
    env_file = Path(".env")
    if not env_file.exists():
        print("❌ .env file not found!")
        print("📝 Please create a .env file with the following variables:")
        print("   ENDPOINT_URL=your_azure_openai_endpoint")
        print("   DEPLOYMENT_NAME=your_model_deployment_name")
        return False
    
    # Check if required variables are present
    with open(env_file, 'r') as f:
        content = f.read()
        if "ENDPOINT_URL" not in content:
            print("⚠️  .env file exists but missing required variables:")
            print("   ENDPOINT_URL=your_azure_openai_endpoint")
            print("   DEPLOYMENT_NAME=your_model_deployment_name")
            return False
    
    return True

def main():
    """Main launcher function"""
    print("🚀 Starting Security Incident Triage Assistant...")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check environment file
    if not check_env_file():
        sys.exit(1)
    
    print("✅ All checks passed! Starting assistant...")
    print("=" * 50)
    
    # Launch the assistant
    try:
        from assistant import main as assistant_main
        assistant_main()
    except KeyboardInterrupt:
        print("\n👋 Assistant stopped by user.")
    except Exception as e:
        print(f"❌ Error starting assistant: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
