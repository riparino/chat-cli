# Use Python 3.11 slim image for security and performance
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Change ownership to non-root user
RUN chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Expose port for health checks (optional)
EXPOSE 8080

# Set environment variables for Azure
ENV PYTHONUNBUFFERED=1
ENV AZURE_CLIENT_ID=""
ENV AZURE_CLIENT_SECRET=""
ENV AZURE_TENANT_ID=""
ENV LOG_ANALYTICS_WORKSPACE_ID=""

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the MCP server
CMD ["python", "main.py"]
