# Secret delivery

`secretvault-server` has two roles. One is the sync hub
([`svserver`](../svserver)), which keeps vaults' files for their devices
and only ever sees ciphertext. The other, described here, delivers secrets
to services, Kubernetes and CI pipelines, from vaults it holds **open**
([`svdeliver`](../svdeliver)). The two share a process and, by default, a
listener; nothing else.

- **Delivery vaults** are ordinary vaults that their owner shared with the
  server's identity (`secretvault share RECIPIENT`). The server reads them
  and never writes to them. Whatever syncs the folder brings changes: this
  server's own hub, or Syncthing, git and the like.
- **Sealed at start.** Operators unseal the server with Shamir shares, k of
  n, or it unseals itself from a systemd credential sealed to the TPM.
- **Machines only.** Tokens, client certificates, or OIDC ID tokens from
  GitHub Actions, GitLab CI and Kubernetes, so pipelines store no secret.
- **Path policies**, deny by default, and a hash-chained audit log.
- **Our own API only**: no Vault or cloud compatibility layers.

[security.md](security.md#the-delivery-server) has its threat model.

## Setting up

```console
# On the server: make the delivery side. It prints the unseal shares, once.
$ secretvault-server init --delivery-dir /var/lib/secretvault/deliver \
      --shares 5 --threshold 3 --admin-token-file ~/admin.token \
      --credential-file /root/unseal.cred          # optional: unattended start

# Serve it beside the sync hub (or on its own address: -deliver-listen ADDR).
$ secretvault-server -root /var/lib/secretvault/server -tls-cert cert.pem -tls-key key.pem \
      -delivery-dir /var/lib/secretvault/deliver

# Any 3 operators, each with their own share, from anywhere:
$ export SECRETVAULT_SERVER=https://secrets.example.com:8443
$ secretvault-server unseal            # asks for the share without echo
Sealed: 1 of 3 shares given (forgotten at 10:42AM).
```

The admin commands then need `--admin-token-file` (or
`$SECRETVAULT_ADMIN_TOKEN_FILE`), and `--fingerprint FP` for a server with a
self-signed certificate.

```console
# A vault: synced to this server under the name 'a1b2...', or any folder.
$ secretvault-server deliver add-vault prod --sync a1b2c3d4e5f60718293a4b5c6d7e8f90
Delivery vault prod is /var/lib/secretvault/server/vaults/a1b2.../files (vault a1b2...).
It is not open yet: it has not been shared with the server: ...

On a device that opens it, share it with the server:
    secretvault share sv-recipient-1-modern-... --label delivery-server

# Who may read what.
$ secretvault-server token create billing-svc --ttl 720h --cidr 10.0.0.0/8
svdt_...
$ secretvault-server role set billing-svc --token billing-svc --allow 'prod:billing/*:read,list'
```

The delivery directory holds:

| File | What | Readable by a thief |
| --- | --- | --- |
| `seal.json` | the root key sealed under the unseal key (and the credential key), the server's identities sealed under the root key, the audit log's public key | no |
| `policy.sealed` | vaults, issuers, the client CA, roles, token hashes, the admin token's hash, sealed and authenticated under the root key | no |
| `audit.log` | one sealed entry per request, chained | no |
| `config.json` | settings: `session_ttl` (15m), `unseal_timeout` (10m), `unseal_credential` (`secretvault-unseal`), `rate` (20 a second per address) | yes; nothing in it grants access |

### Unattended start

`init --credential-file F` (or a later `rekey --credential new`) makes a
key of its own for unsealing, besides the shares. Seal it to the machine
and let systemd hand it over:

```console
# systemd-creds encrypt --with-key=tpm2 --name=secretvault-unseal /root/unseal.cred \
      /etc/credstore.encrypted/secretvault-unseal
# shred -u /root/unseal.cred
```

```ini
# /etc/systemd/system/secretvault-server.service
[Service]
ExecStart=/usr/local/bin/secretvault-server -root /var/lib/secretvault/server \
    -tls-cert /etc/secretvault/cert.pem -tls-key /etc/secretvault/key.pem \
    -delivery-dir /var/lib/secretvault/deliver
LoadCredentialEncrypted=secretvault-unseal
StateDirectory=secretvault
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
```

Use `--with-key=tpm2` (or `tpm2+host`): with the host key alone, the key
that opens the credential is on the same disk.

### Sealing and rekeying

```console
$ secretvault-server seal                                    # the admin
$ secretvault-server rekey --shares 5 --threshold 3          # the admin starts it
$ secretvault-server rekey                                   # then 3 operators, each
```

The operator whose share completes the rekey is shown the new shares, to
hand out; the old ones stop working. The root key does not change, so
nothing else does.

## The API

JSON over HTTPS, under `/v1/deliver/`; errors are `{"error": "..."}`.

| Call | What |
| --- | --- |
| `GET /v1/deliver/status` | sealed or not, and the unseal progress. No credential. |
| `POST /v1/deliver/unseal` | `{"share": "SVUS1-..."}`, one per request; or `{"reset": true}`. No credential. |
| `POST /v1/deliver/login/oidc` | `{"role", "jwt"}` → `{"token", "expires", "role", "identity"}`: a session, 15 minutes unless the role says. |
| `GET /v1/deliver/secret/{vault}/{item}` | the item's fields; `?field=NAME` for one, and `&raw=true` for its bare value. |
| `GET /v1/deliver/list/{vault}/{prefix}` | the item names under the prefix that the caller may list. |
| `/v1/deliver/admin/...` | tokens, roles, vaults, issuers, the client CA, seal, rekey, the audit log: with the admin token. [`svdeliver`](../svdeliver/doc.go) lists them. |

```console
$ curl -H "Authorization: Bearer $TOKEN" https://secrets.example.com:8443/v1/deliver/secret/prod/billing/db
{"vault":"prod","item":"billing/db","kind":"login","version":"808d...","updated":"2026-09-29T13:42:51Z",
 "secret_field":"password","fields":{"password":"s3cr3t","username":"billing"}}

$ curl -H "Authorization: Bearer $TOKEN" \
      'https://secrets.example.com:8443/v1/deliver/secret/prod/billing/db?field=password&raw=true'
s3cr3t

$ curl -H "Authorization: Bearer $TOKEN" https://secrets.example.com:8443/v1/deliver/list/prod/billing/
{"vault":"prod","prefix":"billing/","items":["billing/db","billing/stripe"]}

$ curl -H "Authorization: Bearer $TOKEN" https://secrets.example.com:8443/v1/deliver/secret/prod/payroll/db
{"error":"no such secret, or not allowed"}

# A client certificate instead of a token:
$ curl --cert client.pem --key client-key.pem https://secrets.example.com:8443/v1/deliver/secret/prod/billing/db

# An ID token, logged in and used in one request:
$ curl -H "Authorization: Bearer $(cat /var/run/secrets/tokens/secretvault)" -H "X-Secretvault-Role: payments" \
      'https://secrets.example.com:8443/v1/deliver/secret/prod/payments/db?field=password&raw=true'

# Or a session, for several requests:
$ curl -d '{"role":"deploy","jwt":"'"$ID_TOKEN"'"}' https://secrets.example.com:8443/v1/deliver/login/oidc
{"token":"svds_...","expires":"2026-09-29T14:00:00Z","role":"deploy","identity":"oidc:github:repo:acme/app:ref:refs/heads/main"}
```

Values that are not UTF-8 come in base64 (`fields_base64`, `value_base64`).
An item the caller may not read gets the same answer as one that does not
exist; a caller whose role covers the name gets a plain "no such secret".

## Machine authentication

| Method | Sent as | Checked |
| --- | --- | --- |
| Token | `Authorization: Bearer svdt_...` | its hash is known and not revoked; not expired; the peer address is in its CIDRs, if it has any |
| Session | `Authorization: Bearer svds_...` | in memory, not expired, its role still exists; gone on seal or restart |
| Client certificate | TLS, with no Authorization header | valid now; a pinned SHA-256 fingerprint matches, or it chains to the client CA for client auth and its subject and SAN match the role's globs. The TLS handshake proved the client holds the key. |
| ID token | `POST /login/oidc`, or `Bearer eyJ...` with `X-Secretvault-Role` | below |

An ID token is verified in our own code:

- **Algorithms.** RS256 (RSA keys of 2048 to 8192 bits), ES256 (P-256) and
  EdDSA (Ed25519) only. `none`, the HMAC algorithms and everything else are
  refused before any key is looked at. A key verifies only its own
  algorithm, and a JWKS key labelled with another `alg` is never used.
- **Keys.** From the issuer's JWKS, by `kid`: found through discovery
  (`{issuer}/.well-known/openid-configuration`, which must name the issuer,
  and its `jwks_uri`, which must be HTTPS), or configured for the issuer.
  Fetched keys are kept for an hour; an unknown `kid` fetches them again, at
  most every 30 seconds. Keys inside the token (`jwk`, `jku`, `x5u`, `x5c`)
  are ignored.
- **Claims.** `iss` exactly the issuer's; `aud` includes one of its
  audiences; `exp` required; `exp`, `nbf` and `iat` with a minute's
  leeway. Then every claim the role names must match its glob.
- **Shape.** At most 16 KiB; canonical unpadded base64url; a `crit` header
  is refused; a member named twice in the header or claims is refused.

## Policies

A role names **one** identity and its rules:

```json
{
  "name": "deploy",
  "oidc": {
    "issuer": "github",
    "claims": {"repository": "acme/app", "ref": "refs/heads/main", "environment": "prod"}
  },
  "rules": [
    {"vault": "prod", "items": "app/*", "capabilities": ["read"]},
    {"vault": "prod", "items": "*", "capabilities": ["list"]}
  ],
  "ttl": "20m"
}
```

- **The identity** is one of `"token": "NAME"`,
  `"cert": {"subject": "CN=app,O=Acme", "san": "spiffe://acme/app/*", "fingerprint": "ab12..."}`
  (every condition given must hold; a subject or SAN only of a certificate
  that chains to the client CA), or `"oidc": {"issuer", "claims"}`.
- **Claims** are matched by glob. A claim inside an object is named by its
  path with `/`: `kubernetes.io/namespace`. An array matches if any element
  does. Claims the role does not name do not matter, but it must name at
  least one with something other than wildcards: an issuer such as GitHub
  signs for everyone who asks.
- **Rules** are a vault (glob), an item glob, and capabilities: `read`
  (fields) and `list` (names). In globs `*` is any run of characters, `/`
  included, and `?` any one.
- **Deny by default.** A request made with a token or certificate has every
  role that names it; a session has the role it logged in to. Only the
  delivery vaults are reachable at all.

`secretvault-server role set NAME --file role.json` takes the JSON, or
build it from flags: `--token T`, `--oidc ISSUER --claim K=GLOB...`,
`--cert-subject G --cert-san G --cert-fingerprint FP`, and
`--allow VAULT:ITEMS[:read,list]`.

## GitHub Actions

```console
$ secretvault-server issuer set github --url https://token.actions.githubusercontent.com \
      --audience https://secrets.example.com:8443
$ secretvault-server role set deploy --oidc github --claim repository=acme/app \
      --claim ref=refs/heads/main --claim environment=prod --allow 'prod:app/*'
```

```yaml
name: deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write     # lets the job ask GitHub for its ID token
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod
    env:
      SECRETVAULT_SERVER: https://secrets.example.com:8443
      SECRETVAULT_SERVER_FINGERPRINT: ${{ vars.SECRETVAULT_FINGERPRINT }}  # for a self-signed server
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - run: go install github.com/codemodify/secretvault/cmd/secretvault@latest
      # Into the environment of the later steps, masked in the log:
      - run: secretvault ci fetch --role deploy --github-env DB_PASSWORD=sv://prod/app/db#password
      # Or only for one command:
      - run: secretvault ci run --role deploy --env API_KEY=sv://prod/app/api -- ./deploy.sh
```

`secretvault ci` asks GitHub for a token whose audience is the server's URL
(`--audience` to change it), logs in to the role, and fetches. The
repository stores nothing secret.

## GitLab CI

```console
$ secretvault-server issuer set gitlab --url https://gitlab.com --audience https://secrets.example.com:8443
$ secretvault-server role set gl-deploy --oidc gitlab --claim project_path=acme/app \
      --claim ref_type=branch --claim ref=main --claim ref_protected=true --allow 'prod:app/*'
```

```yaml
deploy:
  id_tokens:
    SECRETVAULT_ID_TOKEN:
      aud: https://secrets.example.com:8443
  script:
    - secretvault ci run --server https://secrets.example.com:8443 --role gl-deploy
        --env DB_PASSWORD=sv://prod/app/db#password -- ./deploy.sh
```

For a self-hosted GitLab, `--url` is its address; `--ca-file` trusts a
private CA. Another variable name than `SECRETVAULT_ID_TOKEN` is given with
`--id-token-env`.

## Kubernetes

The server verifies the cluster's service-account tokens. With the
cluster's discovery reachable:

```console
$ secretvault-server issuer set cluster --url https://oidc.example-cluster.com --audience secretvault
```

or, without public discovery, with its keys:

```console
$ kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
https://kubernetes.default.svc.cluster.local
$ kubectl get --raw /openid/v1/jwks > jwks.json
$ secretvault-server issuer set cluster --url https://kubernetes.default.svc.cluster.local \
      --audience secretvault --jwks-file jwks.json      # again when the cluster rotates its keys
$ secretvault-server role set payments --oidc cluster --claim kubernetes.io/namespace=payments \
      --claim kubernetes.io/serviceaccount/name=api --allow 'prod:payments/*'
```

(`--claim sub=system:serviceaccount:payments:api` says the same.) Legacy,
long-lived service-account tokens have no expiry, and are refused.

### A pod, with the CLI

Mount a token for the server's audience, and use it:

```yaml
spec:
  serviceAccountName: api
  containers:
    - name: app
      command: [secretvault, ci, run, --role, payments, --id-token-file, /var/run/secrets/tokens/secretvault,
                --env, DB_PASSWORD=sv://prod/payments/db#password, --, /app/server]
      env:
        - {name: SECRETVAULT_SERVER, value: https://secrets.example.com:8443}
      volumeMounts:
        - {name: token, mountPath: /var/run/secrets/tokens}
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken: {audience: secretvault, expirationSeconds: 3600, path: secretvault}
```

### The Secrets Store CSI driver

`secretvault-csi-provider` ([`svcsi`](../svcsi)) runs on every node and
serves the driver on `/etc/kubernetes/secrets-store-csi-providers/secretvault.sock`.
The driver passes it the pod's own service-account token, for the audience
its CSIDriver asks for:

```console
$ helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver -n kube-system \
      --set 'tokenRequests[0].audience=secretvault'
```

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: secretvault-csi-provider, namespace: kube-system}
spec:
  selector: {matchLabels: {app: secretvault-csi-provider}}
  template:
    metadata: {labels: {app: secretvault-csi-provider}}
    spec:
      containers:
        - name: provider
          image: your-registry/secretvault-csi-provider   # built from cmd/secretvault-csi-provider
          volumeMounts:
            - {name: providers, mountPath: /etc/kubernetes/secrets-store-csi-providers}
      volumes:
        - name: providers
          hostPath: {path: /etc/kubernetes/secrets-store-csi-providers}
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: payments, namespace: payments}
spec:
  provider: secretvault
  parameters:
    server: https://secrets.example.com:8443
    fingerprint: "3ad7c6ad31..."       # or caCert: a PEM; or neither, for a public CA
    role: payments
    audience: secretvault
    objects: |
      db-password=sv://prod/payments/db#password
      tls/key.pem=sv://prod/payments/tls#key
```

A pod mounts it with a `csi` volume (`driver: secrets-store.csi.k8s.io`,
`volumeAttributes: {secretProviderClass: payments}`), and gets the files
its own service account's role allows. Instead of a role, the
`nodePublishSecretRef` may hold a `token`.

### External Secrets Operator

ESO's webhook provider calls the API with a token kept in a Kubernetes
Secret:

```console
$ secretvault-server token create eso --cidr 10.0.0.0/8
$ secretvault-server role set eso --token eso --allow 'prod:payments/*'
$ kubectl -n external-secrets create secret generic secretvault-token --from-literal=token=svdt_...
```

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: secretvault
spec:
  provider:
    webhook:
      url: "https://secrets.example.com:8443/v1/deliver/secret/prod/{{ .remoteRef.key }}?field={{ .remoteRef.property }}"
      method: GET
      headers:
        Authorization: "Bearer {{ .auth.token }}"
      result:
        jsonPath: "$.value"
      secrets:
        - name: auth
          secretRef:
            name: secretvault-token
            namespace: external-secrets
      caBundle: LS0tLS1CRUdJTi...   # base64 of the server's certificate (or its CA), if not public
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata: {name: payments-db, namespace: payments}
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: ClusterSecretStore, name: secretvault}
  target: {name: payments-db}
  data:
    - secretKey: password
      remoteRef: {key: payments/db, property: password}
```

Every `remoteRef` needs a `property` (the field): the store asks for one
field and reads its `value`.

With a service-account JWT instead of a token: the webhook provider cannot
request a projected token itself, so the JWT must be kept fresh in a Secret
by something else (a CronJob running `kubectl create token eso-reader
--audience secretvault --duration 2h`, say), and sent with the role:

```yaml
      headers:
        Authorization: "Bearer {{ .sa.token }}"
        X-Secretvault-Role: eso-reader
      secrets:
        - name: sa
          secretRef: {name: eso-reader-jwt, namespace: external-secrets}
```

## The audit log

```console
$ secretvault-server audit --limit 5
    11 2026-09-29 09:42:52 10.0.3.7        allowed  login oidc:github:repo:acme/app:ref:refs/heads/main (deploy)
    12 2026-09-29 09:42:52 10.0.3.7        allowed  read prod/app/db#password oidc:github:repo:acme/app:ref:refs/heads/main (deploy)
    13 2026-09-29 09:42:53 10.0.9.2        denied   read prod/payroll/db token:billing-svc (billing-svc): no rule allows reading it
    14 2026-09-29 09:43:10 10.0.9.2        denied   login oidc:github:repo:evil/app:ref:refs/heads/main (deploy): the claims do not match: repository="evil/app" (wants "acme/app")
    15 2026-09-29 09:44:00 127.0.0.1       allowed  token.create billing-svc admin
```

Every request but `GET /status` is recorded before it is answered: time,
address, identity, role, operation, vault, item and field, outcome, and why
it was refused. No value, token, ID token or share. Entries are sealed to a
key only the unsealed server holds, and chained; `audit --json` prints one
JSON object per line, for shipping elsewhere.
