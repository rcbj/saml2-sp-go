# saml2-sp

Server-side SAML 2.0 service provider for Go. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. Publishing is not set up.

## Usage

```go
sp, err := saml.FromFile("saml.json", nil, nil)
relay := "/home"
request, err := sp.Login(saml.LoginOptions{RelayState: &relay})
who, err := sp.Acs(method, rawURL, body, []string{request.ID})
```

The module is `github.com/rcbj/saml2-sp-go` and the package is `saml`. `saml.json` uses the same keys as the Python service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, and is stored as `signals: false`. Any other value is a configuration error: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

`Login` returns a redirect URL or `PostFormHTML` fields. `Acs` accepts a POST body as a string or a map. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`.

```bash
go run ./cmd/saml2-sp generate-keys --config demo/saml.json
go run ./cmd/saml2-sp metadata --config demo/saml.json
```

## Shared Signals

```go
receiver, err := saml.NewSignalsReceiver(saml.ReceiverOptions{
    Transmitter: "https://idp.example",
    OnEndSessions: func(ids []string, event *saml.SignalEvent) error { return nil },
})
receiver.Track(localID, login, nil)
err = receiver.Start()
receiver.Stop()
```

The receiver discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. `Stop` waits until a poll already running has finished. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`.

## Tests

```bash
go test ./...
```

Signatures and decryption are real (`crypto/rsa`, exclusive XML canonicalization). The stub identity provider is in the test files. No live iya-sts. Keys are generated in the test.

## Demo

`go run ./cmd/demo`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls `go run ./cmd/saml2-sp` for keys, metadata, and the identity-provider summary. The container `PORT` wins over the shell `PORT`.
