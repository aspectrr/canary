# Multi-stage build for Next.js standalone output.
# Build with Bun (matches bun.lock); run with Node.

# ---- deps ----
# The latest oven/bun image is 1.3.14; Bun 1.4.0 (which made our v2 lockfile)
# isn't on Docker Hub yet. So we resolve fresh from package.json's pinned
# versions instead of the lockfile.
FROM oven/bun:1.3.14-debian AS deps
WORKDIR /app
COPY package.json ./
RUN bun install

# ---- builder ----
FROM oven/bun:1.3.14-debian AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Next config reads NEXT_PUBLIC_BASE_PATH (defaults to /canary). Override at
# build time only if you mount at a different path.
ENV NEXT_TELEMETRY_DISABLED=1
RUN bun run build

# ---- runner ----
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Standalone server must listen on all interfaces for Fly to reach it.
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

# Next.js standalone build runs as a non-root user by convention.
RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 nextjs

# standalone server.js + the static/public assets it serves.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
