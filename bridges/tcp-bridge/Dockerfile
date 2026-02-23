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
ENV PORT=8080

# App + production dependencies
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

EXPOSE 8080

# Healthcheck without curl/wget (distroless has neither)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "require('http').get({host:'127.0.0.1',port:process.env.PORT||8080,path:'/health',timeout:2000},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]


# distroless:nonroot already runs as non-root
USER nonroot

# distroless node image has ENTRYPOINT ["node"], so this runs: node dist/index.js
CMD ["dist/index.js"]