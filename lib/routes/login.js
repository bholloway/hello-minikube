'use strict';

const Boom = require('boom');


// TODO this needs to be HTTPS
module.exports = ({validateUser, createIdToken, revokeIdToken, createAccessToken}) => {

  const loginHandler = (request, reply) => {
    const {credentials} = request.auth;
    const {id, scope} = credentials;
    Promise.all([
      createIdToken(credentials)
        .catch((message) => reply(Boom.badImplementation(message))),
      createAccessToken({id, scope})
        .catch((message) => reply(Boom.badImplementation(message)))
    ])
      .then(([id_token, access_token]) => reply({id_token, access_token}).code(201));
  };

  return [
    {
      method: 'GET',
      path: '/login',
      config: {
        auth: 'user-basic',
        handler: loginHandler
      }
    },
    {
      method: 'POST',
      path: '/login',
      config: {
        auth: 'user-payload',
        handler: loginHandler
      }
    },
    {
      method: 'GET',
      path: '/logout',
      config: {
        auth: 'id-token',
        handler: (request, reply) => {
          const {credentials} = request.auth;
          revokeIdToken(credentials)
            .then(() => reply().code(200))
            .catch((message) => reply(Boom.badImplementation(message)));
        }
      }
    },
    {
      method: 'GET',
      path: '/refresh',
      config: {
        auth: 'id-token',
        handler: (request, reply) => {
          const {credentials: {id, scope}} = request.auth;
          createAccessToken({id, scope})
            .then((access_token) => reply({access_token}).code(201))
            .catch(({message}) => reply(Boom.badImplementation(message)));
        }
      }
    }
  ];
};
