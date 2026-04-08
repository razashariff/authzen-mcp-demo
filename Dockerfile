FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY public ./public
ENV PORT=3300
EXPOSE 3300
CMD ["node", "server.js"]
