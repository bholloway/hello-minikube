'use strict';


module.exports = () => {
  return [
    {
      method: 'GET',
      path: '/',
      config: {
        auth: 'access-token',
        handler: (req, res) => {
          res(`GET / ${JSON.stringify(req.auth.credentials)}`);
        }
      }
    }
  ];
};
