# Vulnerable Docker Setup - DO NOT USE IN PRODUCTION!

FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping \
    curl \
    vim \
    net-tools \
    procps \
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
COPY static/ static/

# Create necessary directories
RUN mkdir -p uploads exploits

# Add a flag file in the container
RUN echo "FLAG{you_are_inside_the_container}" > /flag.txt

# VULNERABILITY: Run as root user (intentional for privilege escalation practice)
# In production, you should NEVER run containers as root

# Expose port
EXPOSE 5000

# VULNERABILITY: Debug mode enabled
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

# Start the application
CMD ["python", "app.py"]
