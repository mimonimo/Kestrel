# ---------- deps ----------
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps

# ---------- builder ----------
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# NEXT_PUBLIC_* 는 빌드 시점에 클라이언트 번들에 인라인됨. compose 또는 CI 가
# --build-arg 로 주입 — 미지정 시 default (/api/v1) = 같은 origin 의 Caddy 가 /api 를
# backend 로 라우팅하는 운영(EC2) 형태에 맞음. 로컬 docker-compose 에서 host port 직접
# 노출 모드로 띄울 경우엔 compose 에서 NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
# 로 override.
ARG NEXT_PUBLIC_API_BASE_URL=/api/v1
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
RUN npm run build

# ---------- runner ----------
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
