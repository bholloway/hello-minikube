FROM node:6.11.5
EXPOSE 8080
COPY index.js .
CMD node index.js
