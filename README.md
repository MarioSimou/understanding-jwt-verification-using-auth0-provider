### Description

This repository implements a simple express server that runs authentication either using [auth0](https://auth0.com/) or [AWS cognito](https://aws.amazon.com/cognito/) providers.

Both providers expose endpoints that conform the JWKs and JWK protocol, meanining that a client can fetch the necessary keys from each provider and use the keys to verify incoming request to their server. In this repository we demonstrate the below steps:

1. Fetch public keys and filter them based on `kid` identifier.
2. Convert a JWK into a PEM key, which is then used as a secret during the JWT verification.
3. Verify JWT token. If the verification succeeds then the request can access our controller, otherwise we return a 401 status code.

### Documentation

- [Navigating RS256 and JWKs](https://auth0.com/blog/navigating-rs256-and-jwks/#RS256-vs-HS256)
- [JWK RFC](https://datatracker.ietf.org/doc/html/rfc7517#section-4)
- [auth0 Docs - Tokens](https://auth0.com/docs/secure/tokens)
