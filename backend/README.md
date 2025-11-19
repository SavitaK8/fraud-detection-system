🛡️ Fraud Detection System - Backend
Real-Time Fraud Detection using AI/ML - FastAPI Backend

🚀 Quick Start
Installation

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
Training ML Model
bash
# Train the Random Forest classifier
python -m app.models.ml_model
Running the Server
bash
# Start FastAPI development server
uvicorn app.main:app --reload

# Server runs at: http://localhost:8000
# API docs at: http://localhost:8000/api/docs
📡 API Endpoints
POST /api/analyze/url - Analyze URL for threats
POST /api/analyze/email - Analyze email/text content
POST /api/analyze/phone - Analyze phone number
POST /api/analyze/image - Analyze image with OCR
GET /api/health - Health check
GET /api/stats - System statistics
🎯 Features
12-Layer URL Detection
ML-based Phishing Classification (90%+ accuracy)
Typosquatting Detection (Levenshtein distance)
OCR Text Extraction (Tesseract)
Phone Number Validation
Real-time Analysis (<500ms)
📁 Project Structure
backend/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── models/              # ML models & Pydantic schemas
│   ├── detection/           # Detection engines
│   ├── utils/               # Utility functions
│   └── api/                 # API routes
├── data/                    # Training data & models
├── tests/                   # Unit tests
└── requirements.txt         # Dependencies
🧪 Testing
bash
# Test ML model
python -m app.models.ml_model

# Run unit tests
pytest

👥 Team
Savita Kumari
Ruchir Jain
Shivam Singh
Sonu Kumar
ITS Engineering College - CSE Project 2025-2026

