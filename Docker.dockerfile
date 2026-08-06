# Docker containerization config for isolated safe scanning environment
FROM node:18-slim

# Install system dependencies needed for compiling and fuzzing (AFL++/Clang/ASan)
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    build-essential \
    python3 \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set up work directory
WORKDIR /app

# Copy lock and package lists first to optimize build cache
COPY package*.json ./

# Install npm dependencies
RUN npm install

# Copy application files
COPY . .

# Set default ports
EXPOSE 3000

# Set default start command (Fastify API server)
CMD ["node", "fastify-server.js"]
