'use strict';


module.exports = ({users}) => {
  return [
    {
      method: 'POST',
      path: '/login',
      config: {
        handler: (_, res) => {
          res({id_token: createToken({scope: ['user', 'admin']})}).code(201);
        }
      }
    },
    {
      method: 'GET',
      path: '/api',
      config: {
        auth: 'jwt',
        handler: (req, res) => {
          res(`hello GET ${Object.keys(req)}`);
        }
      }
    }
  ];
};
