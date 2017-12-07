'use strict';

const Boom = require('boom');
const {assert, clone} = require('hoek');


exports.register = (plugin, options, next) => {
  plugin.auth.scheme('login', (server, options) => {
    assert(
      !!options && typeof (options === 'object'),
      'Missing login auth strategy options'
    );

    const {unauthorizedAttributes, validateFunc} = clone(options);
    assert(
      (typeof validateFunc === 'function'),
      'options.validateFunc must be a valid function in login scheme'
    );

    return {
      options: {
        payload: true
      },
      authenticate: (request, reply) => {
        return reply.continue({credentials: {}});
      },
      payload: (request, reply) => {
        const {username, password} = request.payload || {};
        if (!username) {
          return reply(Boom.unauthorized(
            'authentication payload is missing username',
            'Login',
            unauthorizedAttributes
          ));
        }

        if (!password) {
          return reply(Boom.unauthorized(
            'authentication payload is missing password',
            'Login',
            unauthorizedAttributes
          ));
        }

        validateFunc(request, username, password, (err, isValid, credentials) => {
          if (err) {
            return reply(err);
          }
          if (!isValid) {
            return reply(
              Boom.unauthorized('Bad username or password', 'Login', unauthorizedAttributes)
            );
          }
          if (!credentials || (typeof credentials !== 'object')) {
            return reply(
              Boom.badImplementation('Bad credentials object received for Login auth validation')
            );
          }
          Object.assign(request.auth.credentials, credentials);
          return reply.continue();
        });
      }
    };
  });

  next();
};

exports.register.attributes = {
  pkg: require('../../package.json')
};
