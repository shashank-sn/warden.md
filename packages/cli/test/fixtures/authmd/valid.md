# auth.md

Agent registration guidance.

## Discover

Read [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource).
Issuer: https://auth.service.test

## Pick a method

Use identity_assertion, service_auth, or anonymous registration as appropriate.

## Register

Register at the identity endpoint described in metadata.

## Claim ceremony

Present the verification URI and user code to the user.

## Exchange the assertion

Exchange an identity assertion at the token endpoint.

## Use the access_token

Present a bearer access token to the resource server.

## Errors

Handle documented OAuth and registration errors.

## Revocation

Use the published revocation endpoint.
