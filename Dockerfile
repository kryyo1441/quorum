# One image for every workspace service. Pick the service with --build-arg PKG=@uw/<name>.
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/* && npm i -g pnpm@10
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @uw/shared build && pnpm --filter @uw/log-server db:generate
ARG PKG
ENV PKG=$PKG
RUN if [ "$PKG" = "@uw/web" ]; then pnpm --filter @uw/web build; fi
CMD pnpm --filter "$PKG" start
