# Hello Minikube

Base on the official kubernetes tutorial

The npm `scripts` in the `package.json` should be self explanatory.

## Testing auth

Basic login

```sh
curl http://fred:flintstone@localhost:8080/login -v
```

Payload login

```sh
curl http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "fred", "password": "flintstone"}' \
  -v
```

Root route with bearer token

```sh
curl http://localhost:8080/ \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -v
```
