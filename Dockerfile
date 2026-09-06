# Multi-stage Dockerfile for Aegis Gateway
# Persistence note: Mount a persistent volume at /app/data to preserve SQLite event logs and approval states across container restarts:
#   docker run -d -p 4310:4310 -v aegis-data:/app/data --name aegis aegis-gateway:latest

# --- Build Stage ---
FROM node:24-alpine AS builder

WORKDIR /app

# Install dependencies needed for build
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code and build
COPY tsconfig.json ./
COPY src/ ./src/
COPY public/ ./public/
RUN npm run build

# Prune dev dependencies for lean production image
RUN npm prune --omit=dev

# --- Production Stage ---
FROM node:24-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=4310 \
    HOST=0.0.0.0 \
    DATABASE_PATH=/app/data/aegis.sqlite

# Create data directory with permissions for the non-root node user
RUN mkdir -p /app/data && chown -R node:node /app

# Copy runtime assets from builder
COPY --chown=node:node package.json ./
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node --from=builder /app/public ./public

# Drop privileges to standard non-root node user
USER node

# Expose HTTP port
EXPOSE 4310

# Container healthcheck using Node 24 native fetch
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4310/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Start production server
CMD ["node", "dist/server.js"]
