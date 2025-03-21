FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir Flask dockerfile-parse nvdlib

RUN freshclam

EXPOSE 5000


CMD ["python", "app.py"]
