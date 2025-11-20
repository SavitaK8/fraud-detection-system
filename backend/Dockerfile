# backend/Dockerfile
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# system packages needed for many python wheels
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential gcc libpq-dev libffi-dev libssl-dev \
      libxml2-dev libxslt1-dev zlib1g-dev libjpeg-dev libglib2.0-0 \
      libsm6 libxrender1 libfontconfig1 && \
    rm -rf /var/lib/apt/lists/*

# upgrade pip & friends to avoid metadata/build errors
RUN python -m pip install --upgrade pip setuptools wheel

# copy requirements then install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy project files
COPY . .

# expose fallback port
EXPOSE 8000

# start the app using Railway's $PORT if present, otherwise fall back to 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]