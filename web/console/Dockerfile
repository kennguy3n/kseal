# Build stage: install deps and produce the static bundle.
FROM node:22-alpine AS build
WORKDIR /app

# Install with a clean, reproducible tree first for better layer caching.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Vite inlines VITE_* at build time. docker-compose passes this build arg; the
# runtime env.js (below) can still override it per deployment without rebuild.
ARG VITE_KSEAL_API_BASE_URL=http://localhost:8080
ENV VITE_KSEAL_API_BASE_URL=$VITE_KSEAL_API_BASE_URL
RUN npm run build

# Runtime stage: static files served by nginx.
FROM nginx:1.27-alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx-security-headers.conf /etc/nginx/snippets/kseal-security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html

# NoOps runtime config: the stock nginx image runs every script in
# /docker-entrypoint.d before starting. This one renders env.js from
# KSEAL_API_BASE_URL so one prebuilt image is configurable per environment.
COPY docker-entrypoint.sh /docker-entrypoint.d/40-render-kseal-env.sh
RUN chmod +x /docker-entrypoint.d/40-render-kseal-env.sh

EXPOSE 80
