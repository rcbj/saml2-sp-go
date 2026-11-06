# saml2-sp

Go service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. MIT. `develop` and `main` are one commit. A release happens when the library's files changed since the last release's tag: `release.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Usage

`saml.FromFile("saml.json", nil, nil)`, then `Login` and `Acs`. JSON keys match the Python configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Exported names are `FromFile`, `Login`, `Acs`, and `PostFormHTML`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean fails with `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `saml2-sp generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `go test ./...` in `golang:1.27`. GitHub Actions uses that command. Do not run the Go toolchain on the host. The demo image does not run the suite.

Signatures and decryption are real. The stub identity provider signs with this package's exclusive canonicalization and is created inside the tests.

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts (main, memory mode, no persistence, no clustering) and checks credential-change and session-revoked on `GET /live-status`. `IYA_STS_URL` uses a running iya-sts; `IYA_STS_IMAGE` starts one from an image; otherwise it clones and builds main. The registrar runs inside the demo image, never with Go on the host. Default ports 18522 (iya-sts) and 18622 (demo), `LIVE_STS_PORT` / `LIVE_DEMO_PORT`; it refuses 3000, 8081, and 18481 to 18495. Always a fresh iya-sts: a second registration of the same SP fails. Its order is install script, then demo image build, then run: it copies the checkout (no `demo/generated`, `.git`, `bin`) to a scratch context, builds the image there once, runs the registrar in it (which writes the chain), builds again (only the `demo/` layer changes), checks the image's `demo/generated/idp-ca.pem` equals the saved file (`idpCaInImage` in the JSON), and runs the demo with `sp.key`, `sp.crt` and `idp-metadata.xml` mounted file by file. It never fetches the CA for the demo, rewrites `idpCa`, or mounts a CA; it reads the saved chain only for its own HTTPS client. It prints no line derived from the test password (CodeQL clear-text logging), and every `ssl.SSLContext` in the scripts sets TLS 1.2 as the minimum. `.github/workflows/nightly.yml` runs the unit suite and that script at 07:26 UTC (`26 7 * * *`) and on `workflow_dispatch`. Push CI stays the unit suite.

## Layout

Package `saml` at the module root, `cmd/saml2-sp` and `cmd/demo`, `scripts/configure_iya_sts.py`, `scripts/trust_chain.py`, `scripts/live_iya_sts.py`, `.github/workflows/nightly.yml`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-go-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok`. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout, plus metadata. `GET /live-status` is JSON `{signedIn, subject, receiver, events: [{type, jti}]}`, never an assertion. When `session-revoked` matched no tracked session (the assertion SessionIndex was the assertion id), the demo ends its one local session and untracks it; that is demo code, not the library. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `Stop` waits for an in-flight poll. `scripts/configure_iya_sts.py` uses the `saml2-sp` binary on `PATH` (falling back to `go run`), registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.

## Trust chain (`idpCa`)

`idpCa` (default `file:generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`'s `save_trust_chain()` (the copy the other SAML repos carry; its CLI reads `--config`/`SAML_CONFIG` and `--idp`/`IYA_STS_URL`): the whole chain from `GET /tls/server-certificate`, falling back to the handshake's chain, and prints the path, the anchor's subject and SHA-256. It used to keep only the root from the handshake, and only when the file was missing. `http.go` loads the file with `AppendCertsFromPEM`, which takes every block as a root; Go verifies the host name, and a pin is only the presented leaf being in the file (a forged leaf before the real CAs does not chain). The demo image carries the chain from build time: `.dockerignore` is `.git`, `demo/generated/*`, `!demo/generated/idp-ca.pem` (until this change it excluded only `.git`, so the SP key and metadata went into images), and the demo stage's `COPY demo demo` (after `go build`) lands it at `/app/demo/generated/idp-ca.pem`. With no chain file the same COPY carries nothing from `demo/generated` and the build succeeds. The test stage copies only what the suite reads, so a new chain does not retest. Rebuild the image after re-running the install script against a different iya-sts. A generated test-user password goes to `demo/generated/<user>.password` (0600), never to stdout. `trust_chain_test.go` serves HTTPS from a four-certificate chain and checks the registrar writes all four (published and handshake), prints the anchor and SHA-256, and that the library trusts the file, refuses the wrong host name, and refuses a forged leaf.

## Plain http (#7)

`send` in `http.go` is the one place every fetch goes through (metadata URL, `ArtifactResolve`, SSF configuration, JWKS, stream and poll). It refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) before `http.NewRequest`, and its `CheckRedirect` refuses a redirect to one, naming only the scheme and host[:port] under the fetch's own code; userinfo is never loopback. Before that, `send` refuses any URL (https too) containing whitespace or a control character, without repeating it. No opt-out. `plain_http_test.go` covers each fetch on `http://example.com` and on `http://0.0.0.0:<port>` (which reaches a 127.0.0.1 listener on Linux, so a zero accept count proves no connection), userinfo, loopback still working, redirects (to `0.0.0.0`, and from loopback http and from https to `http://example.com`), whitespace and control characters, and https to a closed port failing as a connection error.

## Releases

A Go module publishes through its tag. A release happens when the library's files changed since the last release's tag: `release.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `release.yml` then asks the module proxy to fetch the version.
