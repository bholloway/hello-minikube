'use strict';

// https://security.stackexchange.com/questions/17421/how-to-store-salt
// https://codahale.com/how-to-safely-store-a-password/
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const hapiAuthBasic = require('hapi-auth-basic');
const hapiAuthBearer = require('hapi-auth-bearer-token');
const hapiAuthJWT = require('hapi-auth-jwt');
const Redis = require('ioredis-mock'); // TODO use actual redis


const SALT = bcrypt.genSaltSync(12); // TODO move this to vault and hard code it!
const PEPPER = SALT.split('$').pop();

const genRandom = () =>
  bcrypt.genSaltSync(1).split('$').pop();

const genSecret = (key) =>
  bcrypt.hashSync(key, SALT).split('.').pop();

const pwdHash = key =>
  bcrypt.hashSync(key + PEPPER, 12);

const pwdCompare = (plain, hashed, callback, ...args) =>
  bcrypt.compare(plain + PEPPER, hashed, (err, isValid) => callback(err, isValid, ...args));

const register = (server) => (plugin) => new Promise((resolve, reject) =>
  server.register(plugin, (err) => err ? reject(err) : resolve())
);


const redis = new Redis({ // TODO move to env
  port: 6379,
  host: '127.0.0.1',
  family: 4,
  password: 'password',
  db: 0
});


const setupAuth = ({server}) =>
  Promise.all([hapiAuthBasic, hapiAuthBearer, hapiAuthJWT].map(register(server)))
    .then(() => {
      // IMPORTANT basic auth should only be done over https
      const CONSUMERS = [
        {
          id: 1,
          name: 'someUniqueApi',
          key: genRandom(),
          secretHash: pwdHash(genSecret('someUniqueApi'))
        }
      ];
      server.auth.strategy('consumer', 'basic', {
        validateFunc: (request, key, secret, callback) => {
          const consumer = CONSUMERS.find(({key: candidate}) => (candidate === key));
          if (consumer) {
            const {id, secretHash} = consumer;
            pwdCompare(secret, secretHash, callback, {id, name});
          } else {
            callback(null, false);
          }
        }
      });


      // IMPORTANT basic auth should only be done over https
      const USERS = [
        {
          id: 2,
          name: 'fred',
          username: 'fred',
          passwordHash: pwdHash('flintstone')
        }
      ];
      server.auth.strategy('user', 'basic', {
        validateFunc: (request, username, password, callback) => {
          const user = USERS.find(({username: candidate}) => (candidate === username));
          if (user) {
            const {id, passwordHash} = user;
            pwdCompare(password, passwordHash, callback, {id, name});
          } else {
            callback(null, false);
          }
        }
      });


      // bearer token for refresh
      // refresh tokens are stored in redis
      server.auth.strategy('simple', 'bearer-access-token', {
        allowQueryToken: false,
        allowMultipleHeaders: false,
        accessTokenName: 'token',
        validateFunc: (token, callback) =>
          redis.get(token)
            .then(({credentials, expires}) => {
              if (expires > Date.now()) {
                return callback(null, true, credentials);
              } else {
                const {id} = credentials;
                return Promise.all([
                  redis.del(token),
                  redis.del(id)
                ])
                  .then(() => Promise.reject());
              }
            })
            .catch(() => callback(null, false))
      });
      const createRefreshToken = (credentials) => {
        const {id} = credentials;
        const newToken = genRandom();
        return redis.get(id)
          .then((token) => redis.del(token))
          .then(() => redis.pipeline()
            .set(newToken, credentials)
            .set(id, newToken)
          );
      };


      // actual JWT using refresh token
      server.auth.strategy('jwt', 'jwt', {
        key: PEPPER,
        verifyOptions: {algorithms: ['HS256']}
      });
      const encodeJWT = (tokenPayload) =>
        Promise.resolve(jwt.sign(tokenPayload, PEPPER, {algorithm: 'HS256', expiresIn: '1m'}));


      return {server, encodeJWT, createRefreshToken};
    });

module.exports = setupAuth;
