# OAuth2 Sever

An extensible oauth2 server implementation in Go.

## Unsupported Grant Types

The `implicit` and `password` grants are not supported. Use `auth_code` with
PKCE instead.

## Design Principals

### Opaque Tokens

No JWT based tokens. JWT is too easy to screw up, so instead of going that
route, we generate random, opaque tokens for use in the server.

### No Storage

There are interfaces defined here for what the server requires for storage, but
if one is running an oauth2 server a (valid) assumption is that the underlying
storage likely has some sort of domain significance. Generic storage
implementations will never be able to support the domain in which the server is
running. Thus, this implementation provides only interface and some sample (in
memory) implementations as well as simple structs that implement entities.

### OAuth Client as the Extension Point

The oauth client has a fairly simply interface, but there are other interfaces
here which may be implemented to allow fine tuning which clients are allowed to
do what.
