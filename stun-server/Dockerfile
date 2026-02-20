###############
# Build stage #
###############
FROM node:24-bookworm-slim AS builder
WORKDIR /app

# Install deps (incl dev), build, then prune to prod-only
COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY public ./public
RUN npm run build

# Keep only production deps for the runtime image
RUN npm prune --omit=dev && npm cache clean --force

####################
# Production stage #
####################
# Distroless = minimal attack surface (no shell, no package manager)
FROM gcr.io/distroless/nodejs24-debian12:nonroot AS production
WORKDIR /app

ENV NODE_ENV=production
ENV STUN_PORT=3478
ENV SIGNAL_PORT=9090

# App + production dependencies
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

EXPOSE 3478/udp
EXPOSE 3478/tcp
EXPOSE 9090/tcp

# Healthcheck hits the signaling/health port (auto-detects TLS)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "const m=require(process.env.TLS_CERT_PATH?'https':'http');m.get({host:'127.0.0.1',port:process.env.SIGNAL_PORT||9090,path:'/health',timeout:2000,rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

# distroless:nonroot already runs as non-root
USER nonroot

# distroless node image has ENTRYPOINT ["node"], so this runs: node dist/index.js
CMD ["dist/index.js"]
