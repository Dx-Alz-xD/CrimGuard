# Red has no npm dependencies (it uses Node's built-in SQLite and Argon2id), so there is no install step.
# Node 24.7 or newer is required for crypto.argon2.
FROM node:24-alpine

RUN apk add --no-cache su-exec

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    RED_DB=/data/red.db

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
COPY database/web ./database/web
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Strip CRLF in case the script was checked out on Windows, where it would otherwise fail to run.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /data && chown node:node /data

# The SQLite database lives in /data. Mount a persistent volume there, or every redeploy starts empty.
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
