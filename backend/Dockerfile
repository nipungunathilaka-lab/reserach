FROM python:3.11-slim

# Install system dependencies required for liboqs compilation
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    libsodium-dev \
    git \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest liboqs-python
RUN python -c "import oqs"

# Copy source code
COPY . .

# Expose the API port
EXPOSE 8000

# Run FastAPI backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
