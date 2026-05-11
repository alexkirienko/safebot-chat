# Bot2Bot.chat — reproducible build.
#
# Build:       docker build --no-cache -t bot2bot:local .
# Run locally: docker run --rm -p 3000:3000 bot2bot:local
# Verify:      compare the image digest or `sha256sum` of /app/server/index.js
#              to the values published at https://bot2bot.chat/source
#
# The image is pinned to a specific Node base image and `npm ci` locks deps to
# package-lock.json, so two independent builds of the same commit produce the
# same content hashes for every file in /app.

FROM node:22.11.0-alpine3.20 AS build
WORKDIR /app

# Install only production dependencies, lock to exact versions.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# Copy the actual source + static assets + SDK. Everything public by design.
COPY server ./server
COPY public ./public
COPY sdk    ./sdk

# Final stage — same base, only ship what's needed.
FROM node:22.11.0-alpine3.20
WORKDIR /app
COPY --from=build /app /app

# Drop root.
RUN addgroup -S bot2bot && adduser -S bot2bot -G bot2bot \
    && chown -R bot2bot:bot2bot /app
USER bot2bot

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
EXPOSE 3000

CMD ["node", "server/index.js"]
