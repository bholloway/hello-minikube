// https://auth0.com/blog/hapijs-authentication-secure-your-api-with-json-web-tokens/
'use strict';

const {promisify} = require('util');
const Hapi = require('hapi');
const glob = require('glob');

const setupAuth = require('./lib/auth');

const PORT = 8080;

process.on('unhandledException', (error) => console.error(error));
process.on('unhandledRejection', (error) => console.error(error));

Promise.resolve()
  .then(() => {
    const server = new Hapi.Server();
    server.connection({port: PORT});
    return {server};
  })
  .then(setupAuth)
  .then((context) => {
    const {server} = context;
    return promisify(glob)('/lib/routes/**/*.js', {root: __dirname, nodir: true})
      .then(filenames => {
        filenames.forEach(filename => {
          console.log(`add route ${filename}`);
          [].concat(require(filename)(context))
            .forEach(obj => server.route(obj));
        });
        return context;
      });
  })
  .then(({server}) => {
    console.info(`starting http://localhost:${PORT}`);
    server.start();
  })
  .catch(exception => {
    console.error(exception);
    process.exit(1);
  });
