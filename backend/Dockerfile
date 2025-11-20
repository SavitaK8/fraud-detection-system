# backend/Dockerfile
FROM python:3.11-slim

# avoid prompts during package install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

WORKDIR /app

# system deps commonly needed for wheels / native libs
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      libpq-dev \
      libffi-dev \
      libssl-dev \
      libxml2-dev \
      libxslt1-dev \
      zlib1g-dev \
      libjpeg-dev \
      libglib2.0-0 \
      libsm6 \
      libxrender1 \
      libfontconfig1 \
      && rm -rf /var/lib/apt/lists/*

# upgrade pip/setuptools/wheel to avoid metadata-generation errors
RUN python -m pip install --upgrade pip setuptools wheel

# copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy project source
COPY . .

# expose port (not strictly required for Railway, but useful)
EXPOSE $PORT

# start command (Railway will provide PORT env automatically)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]