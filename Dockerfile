FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    docker.io \
    curl \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir Flask dockerfile-parse nvdlib packaging docker

RUN freshclam

EXPOSE 5000

CMD ["python", "app.py"]