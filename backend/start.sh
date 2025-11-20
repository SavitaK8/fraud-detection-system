#!/bin/bash
python -m app.models.ml_model
uvicorn app.main:app --host 0.0.0.0 --port $PORT