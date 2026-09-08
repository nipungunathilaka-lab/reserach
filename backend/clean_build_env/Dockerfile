FROM python:3.11-slim

# Install system dependencies required for liboqs compilation
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest liboqs-python

# Copy source code
COPY . .

# Run pytest by default
CMD ["pytest", "test_mlkem.py", "-v"]
