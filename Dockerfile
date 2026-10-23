# lhns fork Dockerfile, replacing upstream's. Node 22, not upstream's 21: package.json requires
# engines 22.x. Dependabot keeps node below 23 (.github/dependabot.yml).
FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS packages
WORKDIR /usr/src/app
# Prisma's schema engine dlopens libssl and bookworm-slim has none: `prisma migrate deploy`
# then fails with a bare "Schema engine error". The builder stage inherits this too.
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci

FROM packages AS builder
COPY . .
RUN npx prisma generate
RUN npm run build

# A fresh base, not `FROM packages`: devDependencies stay out of the runtime image. `prisma` is a
# production dependency, so the migrate initContainer still has the CLI.
FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS app
WORKDIR /usr/src/app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=builder /usr/src/app/prisma ./prisma
COPY --from=builder /usr/src/app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /usr/src/app/dist ./dist
# Upstream's `COPY .env.example ./.env` is dropped on purpose. The app loads dotenv, which
# fills every variable the environment leaves unset, and .env.example would bake in
# CORS_ORIGINS=https://app.jetkvm.com,http://localhost:5173 and a localhost DATABASE_URL.
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
CMD ["node", "./dist/index.js"]
