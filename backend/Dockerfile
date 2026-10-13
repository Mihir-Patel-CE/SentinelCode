# SentinelCode Production Dockerfile for Render Web Service
FROM python:3.12-slim

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"

# Install LLVM / Clang compiler toolchain and standard C/C++ development headers
# - clang: Clang C compiler executable
# - llvm: LLVM tools and libraries
# - build-essential: libc6-dev and libstdc++-dev for <stdio.h>, <stdlib.h>, <iostream>
# - ca-certificates & curl: Required for HTTPS outbound requests & health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    build-essential \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Validate compiler installation directly during container build
RUN clang --version && clang++ --version

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY . .

# Expose Render default port
EXPOSE 8000

# Start FastAPI application binding to Render $PORT (fallback to 8000)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
