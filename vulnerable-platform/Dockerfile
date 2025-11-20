# Simplified Vulnerable Docker Setup - Educational Purposes Only!

FROM python:3.9-slim

# Install minimal dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/

# VULNERABILITY: Run as root user (intentional)
# In production, you should NEVER run containers as root

# Expose port
EXPOSE 5000

# Debug mode enabled
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

# Start the application
CMD ["python", "app.py"]
