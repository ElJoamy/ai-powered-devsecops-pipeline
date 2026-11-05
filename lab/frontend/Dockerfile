FROM node:22-bookworm-slim

# Educational Docker misconfigurations: USER and HEALTHCHECK omitted on purpose.
# Build context: frontend/. Only the harmless entrypoint enters the image.
WORKDIR /lab
COPY src/index.js ./index.js
CMD ["node", "index.js"]
