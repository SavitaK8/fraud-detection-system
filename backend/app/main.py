

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import time
from typing import Optional

from app.api.routes import router
from app.models.ml_model import PhishingDetector

# Initialize FastAPI app
app = FastAPI(
    title="Real-Time Fraud Detection API",
    description="AI-Powered Multi-Layer Security Analysis System",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS Configuration - Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins like ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ML Model on startup
ml_detector = None

@app.on_event("startup")
async def startup_event():
    """Initialize ML model and resources on startup"""
    global ml_detector
    try:
        print("🚀 Initializing ML Phishing Detection Model...")
        ml_detector = PhishingDetector()
        ml_detector.train()
        print("✅ ML Model loaded successfully!")
        print("=" * 60)
        print("🛡️  FRAUD DETECTION SYSTEM READY")
        print("=" * 60)
        print("📡 API Endpoints:")
        print("   - http://localhost:8000/api/docs (Swagger UI)")
        print("   - http://localhost:8000/api/analyze/url")
        print("   - http://localhost:8000/api/analyze/email")
        print("   - http://localhost:8000/api/analyze/phone")
        print("   - http://localhost:8000/api/analyze/image")
        print("=" * 60)
    except Exception as e:
        print(f"⚠️ Warning: ML model initialization failed: {e}")
        ml_detector = None

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown"""
    print("🛑 Shutting down Fraud Detection System...")

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request, call_next):
    """Add response time header to all responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000  # Convert to ms
    response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
    return response

# Health check endpoint
@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - API health check"""
    return {
        "status": "online",
        "service": "Real-Time Fraud Detection API",
        "version": "1.0.0",
        "ml_model": "active" if ml_detector else "inactive",
        "message": "Welcome to ITS Engineering College Fraud Detection System",
        "project": "CSE Project 2025-2026",
        "team": ["Savita Kumari", "Ruchir Jain", "Shivam Singh", "Sonu Kumar"],
        "endpoints": {
            "docs": "/api/docs",
            "analyze_url": "/api/analyze/url",
            "analyze_email": "/api/analyze/email",
            "analyze_phone": "/api/analyze/phone",
            "analyze_image": "/api/analyze/image",
            "stats": "/api/stats"
        }
    }

@app.get("/api/health", tags=["Health"])
async def health_check():
    """Detailed health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "ml_model_status": "active" if ml_detector else "inactive",
        "components": {
            "url_detector": "operational",
            "email_detector": "operational",
            "phone_detector": "operational",
            "image_detector": "operational",
            "ml_classifier": "active" if ml_detector else "inactive"
        },
        "performance": {
            "target_response_time": "<500ms",
            "target_accuracy": "90%+",
            "target_false_positives": "<5%"
        }
    }

# Include API routes
app.include_router(router, prefix="/api")

# Make ml_detector available to routes
app.state.ml_detector = ml_detector

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle all uncaught exceptions"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "type": type(exc).__name__
        }
    )

if __name__ == "__main__":
    # Run the server
    print("=" * 60)
    print("🚀 Starting Real-Time Fraud Detection System")
    print("=" * 60)
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
