# toolzyhub-api - Node.js/Express Backend
# Using Debian slim for glibc compatibility with onnxruntime
FROM node:22-slim

WORKDIR /app

# Install dependencies for native modules (Sharp, bcrypt, argon2, onnxruntime, etc.)
# plus the PNG compressors the API shells out to (pngquant, advpng, zopflipng).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    libvips-dev \
    libpng-dev \
    autoconf \
    automake \
    libtool \
    nasm \
    pkg-config \
    pngquant \
    advancecomp \
    zopfli \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Create required directories
RUN mkdir -p logs uploads

# Expose port
EXPOSE 3001

# Start development server with nodemon
CMD ["npm", "run", "dev"]
