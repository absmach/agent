# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

# Stage 1 — install deps and build the Vite app
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2 — minimal static server
FROM nginx:1.27-alpine AS runner

COPY --from=builder /app/dist /usr/share/nginx/html/ui
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
