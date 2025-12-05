# syntax=docker/dockerfile:1
ARG NODE_VERSION=20.15.0
FROM node:${NODE_VERSION}-alpine

WORKDIR /usr/src/app

# copy package files, install (as root)
COPY package.json package-lock.json ./
RUN npm ci

# copy rest of sources (as root), run build if needed
COPY . .

# ensure cache & node_modules dirs are writable by the node user
RUN mkdir -p /home/node/.npm \
    && mkdir -p /usr/src/app/node_modules/.cache \
    && chown -R node:node /usr/src/app /home/node/.npm

# switch to non-root user for runtime
USER node

EXPOSE 3000
CMD ["npm", "start"]
