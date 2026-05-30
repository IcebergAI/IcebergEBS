FROM python:3.14-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build version is stamped in (the image has no .git for runtime resolution).
# Pass with: docker build --build-arg MARVIN_VERSION="build 142 · 8ebe5f8" .
ARG MARVIN_VERSION=""
ENV MARVIN_VERSION=$MARVIN_VERSION

RUN chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
