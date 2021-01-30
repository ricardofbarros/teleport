## Teleport Auth Go Client

### Introduction

This program demonstrates how to...

1. Authenticate against the Auth API using certificates.
2. Make API calls to issue CRUD requests for cluster join tokens, roles, and labels.
3. Receive, allow, and deny access requests.

### API Authentication

Auth API clients must perform two-way authentication using x509 certificates:

1. They have to validate the auth server x509 certificate to make sure the
   API endpoint can be trusted.
2. They must offer their x509 certificate, which has been previously issued
   by the auth sever.

There are a few ways to generate the certificates needed to authenticate the client. This
demo uses the default profile, which is generated with `tsh login`.

### API Authorization

The API will authorize requests based on the certs provided. Since these credentials
are created by `tsh login`, the API will authorize requests based on that login.

Note: role based access control is an enterprise feature. All users will be treated 
as the `admin` role in non-enterprise instances of Teleport. 

### Run the Demo

```bash
$ tsh login
$ go run .
```

```bash
$ tctl create -f api-admin.yaml
$ mkdir -p certs
$ tctl auth sign --format=tls --ttl=87600h --user=api-admin --out=certs/api-admin
```