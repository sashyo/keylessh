# KeyleSSH Production Dockerfile
# Multi-stage build for optimized image size

###############
# Build stage #
###############
FROM node:22-bookworm-slim AS builder
WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching)
COPY package*.json ./
RUN npm ci

# Copy source code
COPY tsconfig.json ./
COPY vite.config.ts ./
COPY drizzle.config.ts ./
COPY tailwind.config.ts ./
COPY postcss.config.js ./
COPY components.json ./
COPY server ./server
COPY client ./client
COPY shared ./shared
COPY script ./script

# Build client and server
RUN npm run build

# Prune to production dependencies and rebuild native modules
RUN npm ci --omit=dev && npm cache clean --force

####################
# Production stage #
####################
FROM node:22-bookworm-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r keylessh && useradd -r -g keylessh keylessh

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_URL=/app/data/keylessh.db

# Create data directory
RUN mkdir -p /app/data && chown -R keylessh:keylessh /app

# Copy built application from builder
COPY --from=builder --chown=keylessh:keylessh /app/node_modules ./node_modules
COPY --from=builder --chown=keylessh:keylessh /app/dist ./dist
COPY --from=builder --chown=keylessh:keylessh /app/package.json ./

# Switch to non-root user
USER keylessh

# Volume for persistent data (database + tidecloak.json)
VOLUME ["/app/data"]

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e "require('http').get({host:'127.0.0.1',port:process.env.PORT||3000,path:'/health',timeout:2000},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Run production server
CMD ["node", "dist/index.cjs"]
