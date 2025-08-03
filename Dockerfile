# Multi-stage Docker build for Enhanced IDS System
FROM python:3.9-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iptables \
    iproute2 \
    procps \
    curl \
    wget \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r idsuser && useradd -r -g idsuser idsuser

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/models && \
    chown -R idsuser:idsuser /app

# Expose ports
EXPOSE 8501 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Switch to non-root user
USER idsuser

# Default command (can be overridden)
CMD ["python", "ids.py"]

# Production stage
FROM base as production

# Copy only necessary files for production
COPY --from=base /app /app
WORKDIR /app

# Production optimizations
ENV PYTHONOPTIMIZE=1

# Labels for metadata
LABEL maintainer="IDS Team" \
      version="1.0.0" \
      description="Enhanced Real-Time IDS with ML Detection" \
      org.opencontainers.image.source="https://github.com/your-org/enhanced-ids"

# Dashboard stage
FROM base as dashboard

WORKDIR /app

# Install additional dashboard dependencies
RUN pip install --no-cache-dir streamlit plotly

# Expose Streamlit port
EXPOSE 8501

# Start dashboard
CMD ["streamlit", "run", "professional_dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
