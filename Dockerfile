FROM node:lts-trixie-slim AS test
SHELL ["bash", "-c"]
WORKDIR /home/node

USER node
COPY --chown=node:staff package.json .
RUN npm i
COPY --chown=node:staff app app
COPY --chown=node:staff acl acl
COPY --chown=node:staff db db
COPY --chown=node:staff __test__ __test__
RUN npm test

FROM node:lts-trixie-slim
SHELL ["bash", "-c"]
WORKDIR /home/node
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates sudo \
 && apt-get clean && rm -fr /var/lib/apt/lists/*
RUN echo 'node ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers.d/40-users

USER node
COPY --chown=node:staff package.json .
RUN npm i --omit=dev
COPY --chown=node:staff app app
COPY --chown=node:staff acl acl
COPY --chown=node:staff db db

USER root
EXPOSE 53/udp
CMD ["npm", "start"]
