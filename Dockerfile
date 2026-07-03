FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY openapi.yaml ./
EXPOSE 4010
CMD ["node", "server.js"]
