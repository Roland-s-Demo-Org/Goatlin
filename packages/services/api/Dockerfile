FROM node:10.14.1-alpine

WORKDIR /app
COPY . .
RUN npm install --production
RUN chown -R 1000:1000 /app
USER 1000
CMD npm start
