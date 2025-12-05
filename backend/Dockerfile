# backend/Dockerfile
FROM python:3.12.7-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# copy only requirements first (cacheable)
COPY requirements.txt .

# install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc build-essential \
    && python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt \
    && apt-get remove -y gcc build-essential \
    && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# copy app source
COPY . .

# create non-root user and give ownership of app folder
ARG UID=10001
RUN useradd --create-home --shell /bin/bash --uid ${UID} appuser \
    && chown -R appuser:appuser /app

USER appuser

ENV PORT=5000
EXPOSE 5000

# Use gunicorn if listed in requirements; otherwise fallback to python app.py
CMD ["sh", "-c", "if command -v gunicorn >/dev/null 2>&1; then exec gunicorn -b 0.0.0.0:${PORT} app:app; else exec python app.py; fi"]
