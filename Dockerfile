FROM node:22-alpine

# Install curl and openssl for healthcheck / crypto utilities
RUN apk add --no-cache curl openssl

# Create unprivileged group and user with UID/GID 568
RUN addgroup -g 568 appgroup && \
    adduser -u 568 -G appgroup -s /bin/sh -D appuser

# Set working directory and keys/data storage directories
WORKDIR /app
RUN mkdir -p /app /keys /data && \
    chown -R 568:568 /app /keys /data

# Default environment variables
ENV NODE_ENV=production \
    PORT=30019 \
    HOST=0.0.0.0 \
    KEYS_DIR=/keys \
    KEY_PATH=/keys/private.pem \
    PUBLIC_KEY_PATH=/keys/public.pem \
    DB_PATH=/keys/licenses.sqlite \
    AUTO_GENERATE_KEYS=true

# Copy dependency definition
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev && npm cache clean --force

# Copy application source code
COPY src ./src

# Ensure file ownership for user 568
RUN chown -R 568:568 /app

# Volume for persisted keys and database
VOLUME ["/keys"]

# Expose service port 30019
EXPOSE 30019

# Switch to user 568
USER 568:568

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:${PORT:-30019}/healthz || exit 1

# Start license server
CMD ["node", "src/server.js"]
