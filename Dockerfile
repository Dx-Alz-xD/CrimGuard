# Red uses Node's built-in SQLite and Argon2id (Node 24.7 or newer). The only package is the
# optional PostgreSQL driver for the CrimGuard risk database.
FROM node:24-alpine

RUN apk add --no-cache su-exec

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    RED_DB=/data/red.db \
    CRIMGUARD_SQLITE_PATH=/data/crimguard.db

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
COPY database/web ./database/web
COPY database/crimguard ./database/crimguard
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Strip CRLF in case the script was checked out on Windows, where it would otherwise fail to run.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /data && chown node:node /data

# The SQLite databases live in /data. Mount a persistent volume there, or every redeploy starts empty.
# Without CRIMGUARD_DATABASE_URL, /data/crimguard.db is built from database/crimguard/ on first start.
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
