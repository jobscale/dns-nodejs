FROM node:lts-bookworm-slim
SHELL ["bash", "-c"]
WORKDIR /home/node
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  iproute2 dnsutils netcat-openbsd \
 && apt-get clean && rm -fr /var/lib/apt/lists/*

COPY --chown=node:staff package.json .
RUN npm i --omit=dev
COPY --chown=node:staff app app
COPY --chown=node:staff acl acl

EXPOSE 53/udp
CMD ["npm", "start"]
