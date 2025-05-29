# 1. Base image: lightweight Python runtime
FROM python:3.11-slim

# 2. Switch into the /app directory
WORKDIR /app

# 3. Copy your dependency list and install them
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy your server code into the image
COPY app.py crypto.py /app/

# 5. Tell Docker the container listens on port 5000
EXPOSE 5000

# 6. When the container starts, run Gunicorn with Eventlet for WebSockets
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
