# Dockerfile for a Python Flask application (production-ready with gunicorn)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=5000

WORKDIR /app

# Install build deps for wheels; adjust or remove if not needed
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./

RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Create unprivileged user and set ownership
RUN groupadd -r app && useradd --no-log-init -r -g app app \
    && chown -R app:app /app

USER app

EXPOSE 5000

# Default command expects gunicorn in requirements and an app callable at "app:app"
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]