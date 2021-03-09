FROM node:alpine
ENV dst /opt/nodejs/radius
RUN mkdir -p $dst
WORKDIR $dst
COPY . .
ENTRYPOINT ["nodejs", "server.js"]