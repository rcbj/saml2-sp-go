// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Plain http is refused off loopback for every fetch (#7): the metadata URL,
// the ArtifactResolve and the Shared Signals transmitter.

const plainRefusal = "plain http is allowed only to a loopback host"

// countingListener accepts on 127.0.0.1 and counts every connection. On
// Linux, http://0.0.0.0:<port> reaches it, so a count of zero after a
// refusal proves the refusal came before any connection.
type countingListener struct {
	listener net.Listener
	accepted atomic.Int32
	port     string
}

func startCounting(t *testing.T) *countingListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	holder := &countingListener{listener: listener}
	_, holder.port, _ = net.SplitHostPort(listener.Addr().String())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			holder.accepted.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return holder
}

func (c *countingListener) assertUntouched(t *testing.T) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	if n := c.accepted.Load(); n != 0 {
		t.Fatalf("the listener saw %d connection(s); the refusal must come before connecting", n)
	}
}

func metadataFrom(source string) error {
	_, err := Create(testConfig(map[string]any{"idpMetadata": source}, ""), "", nil)
	return err
}

func artifactThrough(t *testing.T, ars string) error {
	t.Helper()
	sp := mustSP(t, nil, ars)
	_, err := sp.Acs("GET", "/saml/acs?SAMLart="+url.QueryEscape(artifactFor("")), nil, []string{"_r"})
	return err
}

func transmitterAt(t *testing.T, transmitter string) error {
	t.Helper()
	receiver, err := NewSignalsReceiver(ReceiverOptions{Transmitter: transmitter, Log: quietLog{}, OnEndSessions: func([]string, *SignalEvent) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Stop()
	return receiver.Start()
}

func TestRefusesPlainHttpOffLoopbackForEveryFetch(t *testing.T) {
	rejects(t, func() error { return metadataFrom("http://example.com/saml/metadata") }, "metadata", `^http://example\.com is refused: `+plainRefusal)
	rejects(t, func() error { return artifactThrough(t, "http://example.com/ars") }, "artifact", `^http://example\.com is refused: `+plainRefusal)
	rejects(t, func() error { return transmitterAt(t, "http://example.com") }, "ssf", `^http://example\.com is refused: `+plainRefusal)
}

func TestRefusesPlainHttpBeforeConnecting(t *testing.T) {
	stub := startCounting(t)
	origin := "http://0.0.0.0:" + stub.port
	rejects(t, func() error { return metadataFrom(origin + "/saml/metadata") }, "metadata", plainRefusal)
	rejects(t, func() error { return artifactThrough(t, origin+"/ars") }, "artifact", plainRefusal)
	rejects(t, func() error { return transmitterAt(t, origin) }, "ssf", plainRefusal)
	stub.assertUntouched(t)
}

func TestUserinfoIsNeverLoopbackAndIsNotRepeated(t *testing.T) {
	stub := startCounting(t)
	err := metadataFrom("http://alice:s3cret-pass@127.0.0.1:" + stub.port + "/saml/metadata?token=q1")
	rejects(t, func() error { return err }, "metadata", `^http://127\.0\.0\.1:`+stub.port+` is refused: `+plainRefusal)
	for _, leaked := range []string{"alice", "s3cret-pass", "/saml/metadata", "token", "q1"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("the refusal repeats %q: %s", leaked, err)
		}
	}
	rejects(t, func() error { return metadataFrom("http://localhost:80@example.com/saml/metadata") }, "metadata", `^http://example\.com is refused: `+plainRefusal)
	stub.assertUntouched(t)
}

func TestPlainHttpToLoopbackStillWorks(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(idpMetadata("")))
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	for _, host := range []string{"127.0.0.1", "localhost"} {
		if err := metadataFrom("http://" + host + ":" + port + "/saml/metadata"); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}
	if !isLoopbackHost("127.255.0.9") || !isLoopbackHost("::1") || !isLoopbackHost("LOCALHOST") {
		t.Fatal("a loopback host was not loopback")
	}
	for _, host := range []string{"0.0.0.0", "128.0.0.1", "::", "localhost.example.com", "example.com"} {
		if isLoopbackHost(host) {
			t.Fatalf("%s counted as loopback", host)
		}
	}
}

func TestRefusesARedirectToPlainHttpOffLoopback(t *testing.T) {
	stub := startCounting(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://0.0.0.0:"+stub.port+"/saml/metadata", http.StatusFound)
	})}
	go server.Serve(listener)
	defer server.Close()
	rejects(t, func() error { return metadataFrom("http://" + listener.Addr().String() + "/saml/metadata") }, "metadata", `^http://0\.0\.0\.0:`+stub.port+` is refused: `+plainRefusal)
	stub.assertUntouched(t)
}

func TestHttpsToAnUnreachableHostIsAConnectionError(t *testing.T) {
	err := metadataFrom("https://127.0.0.1:1/saml/metadata")
	var samlErr *SamlError
	if !errors.As(err, &samlErr) || samlErr.Code != "metadata" {
		t.Fatalf("expected a metadata error, got %v", err)
	}
	if strings.Contains(samlErr.Message, plainRefusal) || !strings.Contains(strings.ToLower(samlErr.Message), "refused") {
		t.Fatalf("expected a connection error, got %q", samlErr.Message)
	}
}

func TestRefusesARedirectToExampleComFromLoopbackOrHttps(t *testing.T) {
	away := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/saml/metadata", http.StatusFound)
	})
	plain := httptest.NewServer(away)
	defer plain.Close()
	rejects(t, func() error { return metadataFrom(plain.URL + "/saml/metadata") }, "metadata", `^http://example\.com is refused: `+plainRefusal)
	secure := httptest.NewTLSServer(away)
	defer secure.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}))
	rejects(t, func() error {
		_, err := send(secure.URL+"/saml/metadata", "GET", nil, "", &TLSOptions{CA: ca}, "metadata")
		return err
	}, "metadata", `^http://example\.com is refused: `+plainRefusal)
}

func TestRefusesAUrlWithWhitespaceOrAControlCharacter(t *testing.T) {
	stub := startCounting(t)
	for _, raw := range []string{
		"http://127.0.0.1:" + stub.port + "/saml metadata",
		"http://127.0.0.1:" + stub.port + "\t@example.com/",
		"https://127.0.0.1:" + stub.port + "/a\r\nX-Injected: s3cret",
		"http://127.0.0.1:" + stub.port + "/a\x00b",
		"http://127.0.0.1:" + stub.port + "/a\u00a0b",
	} {
		err := metadataFrom(raw)
		rejects(t, func() error { return err }, "metadata", `^a URL containing whitespace or a control character is refused$`)
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("the refusal repeats the URL: %s", err)
		}
	}
	rejects(t, func() error { return transmitterAt(t, "http://127.0.0.1:"+stub.port+"\n") }, "ssf", `whitespace or a control character`)
	stub.assertUntouched(t)
}
