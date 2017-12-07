'use strict';

// https://security.stackexchange.com/questions/17421/how-to-store-salt
// https://codahale.com/how-to-safely-store-a-password/
// https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
const ms = require('ms');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const hapiAuthBasic = require('hapi-auth-basic');
const hapiAuthBearer = require('hapi-auth-bearer-token');
const hapiAuthJWT = require('hapi-auth-jwt');
const Redis = require('ioredis-mock'); // TODO use actual redis

const hapiAuthLogin = require('./plugins/auth-login');


const SALT = bcrypt.genSaltSync(12); // TODO move this to vault and hard code it!
const PEPPER = SALT.split('$').pop();

const ID_TOKEN_TTL = '24hrs';
const ACCESS_TOKEN_TTL = '3min';


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
  Promise.all([hapiAuthBasic, hapiAuthLogin, hapiAuthBearer, hapiAuthJWT].map(register(server)))
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
            const {secretHash, ...credentials} = consumer;
            pwdCompare(secret, secretHash, callback, credentials);
          } else {
            callback(null, false);
          }
        }
      });

      const USERS = [
        {
          id: 2,
          name: 'fred',
          username: 'fred',
          passwordHash: pwdHash('flintstone'),
          scope: ['user', 'admin']
        }
      ];
      const validateUser = (request, username, password, callback) => {
        const user = USERS.find(({username: candidate}) => (candidate === username));
        if (user) {
          const {passwordHash, ...credentials} = user;
          pwdCompare(password, passwordHash, callback, credentials);
        } else {
          callback(null, false);
        }
      };
      server.auth.strategy('user-basic', 'basic', {
        validateFunc: validateUser
      });
      server.auth.strategy('user-payload', 'login', {
        validateFunc: validateUser
      });


      // id-token for access-token refresh
      // id-tokens are stored in redis as id=>token and token=>{credentials,expires}
      const revokeIdToken = ({id} = {}) =>
        (typeof id === 'number') &&
        redis.get(id).then((token) => !!(token && redis.del(token, id)));

      const createIdToken = (credentials) => {
        const {id} = credentials;
        const newToken = genRandom();
        const expires = Date.now() + ms(ID_TOKEN_TTL);
        return revokeIdToken({id})
          .then(() => redis.mset(
            id, newToken,
            newToken, JSON.stringify({credentials, expires}))
          )
          .then(() => newToken);
      };

      // IMPORTANT bearer access-token should only be done over https
      server.auth.strategy('id-token', 'bearer-access-token', {
        allowQueryToken: true, // TODO set the false later, query token is insecure in logs
        allowMultipleHeaders: false,
        accessTokenName: 'id_token',
        validateFunc: (token, callback) =>
          redis.get(token)
            .then((json) => {
              const {credentials, expires} = json ? JSON.parse(json) : {};
              if (expires > Date.now()) {
                callback(null, true, credentials);
              } else if (credentials) {
                const {id} = credentials;
                redis.del(token, id).then(() => callback(null, false));
              } else {
                callback(null, false);
              }
            })
      });

      // access-token
      const createAccessToken = (tokenPayload) =>
        Promise.resolve(
          jwt.sign(tokenPayload, PEPPER, {algorithm: 'HS256', expiresIn: ACCESS_TOKEN_TTL})
        );

      server.auth.strategy('access-token', 'jwt', {
        key: PEPPER,
        verifyOptions: {algorithms: ['HS256']}
      });

      return {server, validateUser, createIdToken, revokeIdToken, createAccessToken};
    });

module.exports = setupAuth;
