# One image for every workspace service. Compose picks the service with `command: pnpm --filter @uw/<name> start`.
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/* && npm i -g pnpm@10
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @uw/shared build && pnpm --filter @uw/log-core build && pnpm --filter @uw/witness-core build && pnpm --filter @uw/client-sdk build && pnpm --filter @uw/log-server db:generate
RUN pnpm --filter @uw/web build
# the service is chosen at run time (compose `command`), so every service shares this one image
CMD ["pnpm", "--filter", "@uw/web", "start"]
