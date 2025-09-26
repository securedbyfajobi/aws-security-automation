# AWS Security Automation Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    jq \
    awscli \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Terraform
RUN curl -fsSL https://releases.hashicorp.com/terraform/1.9.0/terraform_1.9.0_linux_amd64.zip -o terraform.zip && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform.zip

# Create non-root user for security
RUN groupadd -r security && useradd -r -g security security

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
    boto3==1.29.0 \
    botocore==1.32.0 \
    python-dotenv==1.0.0 \
    pydantic==2.5.0 \
    click==8.1.7 \
    jinja2==3.1.2 \
    PyYAML==6.0.1 \
    requests==2.31.0 \
    pandas==2.1.4 \
    prometheus-client==0.19.0

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /app/temp && \
    chown -R security:security /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV AWS_DEFAULT_REGION=eu-west-2

# Switch to non-root user
USER security

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import boto3; print('Health check passed')" || exit 1

# Default command
CMD ["python", "-m", "security_automation.main"]

# Labels for metadata
LABEL maintainer="afajobi@securedbyfajobi.com"
LABEL description="AWS Security Automation Suite"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/securedbyfajobi/aws-security-automation"