// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func b64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func jwkOf(key *rsa.PrivateKey, kid string) map[string]any {
	n := key.N.Bytes()
	e := new(big.Int).SetInt64(int64(key.E)).Bytes()
	return map[string]any{"kty": "RSA", "n": b64url(n), "e": b64url(e), "kid": kid, "alg": "RS256", "use": "sig"}
}

func signJWS(payload map[string]any, key *rsa.PrivateKey, header map[string]any) string {
	if header == nil {
		header = map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
	}
	head, _ := json.Marshal(header)
	body, _ := json.Marshal(payload)
	h := b64url(head)
	p := b64url(body)
	alg, _ := header["alg"].(string)
	sig := ""
	if alg != "" && alg != "none" && alg != "HS256" {
		sum := sha256.Sum256([]byte(h + "." + p))
		raw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
		sig = b64url(raw)
	}
	return h + "." + p + "." + sig
}

type txStub struct {
	mu       sync.Mutex
	queue    map[string]string
	acked    []string
	errs     map[string]any
	streams  []map[string]any
	created  int
	url      string
	server   *http.Server
	listener net.Listener
	hold     chan struct{}
	entered  chan struct{}
	once     sync.Once
}

func (s *txStub) close() { _ = s.server.Close() }

func startTransmitter(t *testing.T) *txStub {
	t.Helper()
	stub := &txStub{queue: map[string]string{}, errs: map[string]any{}}
	jwk := jwkOf(txKey, "k1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		path := r.URL.Path
		write := func(status int, body any) {
			var payload []byte
			if body != nil {
				payload, _ = json.Marshal(body)
			}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(payload)
		}
		if path == "/.well-known/ssf-configuration" {
			write(200, map[string]any{
				"issuer": stub.url, "jwks_uri": stub.url + "/jwks",
				"configuration_endpoint": stub.url + "/ssf/stream", "verification_endpoint": stub.url + "/ssf/verify",
				"delivery_methods_supported": []string{pollMethod},
			})
			return
		}
		if path == "/jwks" {
			write(200, map[string]any{"keys": []any{jwk}})
			return
		}
		if path == "/ssf/stream" && r.Method == http.MethodGet {
			stub.mu.Lock()
			streams := append([]map[string]any{}, stub.streams...)
			stub.mu.Unlock()
			write(200, streams)
			return
		}
		if path == "/ssf/stream" && r.Method == http.MethodPost {
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			stub.mu.Lock()
			stub.created++
			delivery, _ := body["delivery"].(map[string]any)
			stream := map[string]any{
				"stream_id": "s" + itoa(stub.created), "iss": stub.url, "aud": "my-app",
				"delivery":         map[string]any{"method": delivery["method"], "endpoint_url": stub.url + "/ssf/poll/s" + itoa(stub.created)},
				"events_requested": body["events_requested"],
				"events_delivered": body["events_requested"],
			}
			stub.streams = append(stub.streams, stream)
			stub.mu.Unlock()
			write(201, stream)
			return
		}
		if strings.HasPrefix(path, "/ssf/poll/") {
			if stub.hold != nil {
				stub.once.Do(func() { close(stub.entered) })
				<-stub.hold
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			stub.mu.Lock()
			if ack, ok := body["ack"].([]any); ok {
				for _, item := range ack {
					jti := stringOf(item)
					stub.acked = append(stub.acked, jti)
					delete(stub.queue, jti)
				}
			}
			if setErrs, ok := body["setErrs"].(map[string]any); ok {
				for jti, value := range setErrs {
					stub.errs[jti] = value
					delete(stub.queue, jti)
				}
			}
			sets := map[string]string{}
			for jti, token := range stub.queue {
				sets[jti] = token
			}
			stub.mu.Unlock()
			write(200, map[string]any{"sets": sets, "moreAvailable": false})
			return
		}
		write(404, map[string]any{"err": "not found"})
	})
	stub.listener = listener
	stub.server = &http.Server{Handler: mux}
	go stub.server.Serve(listener)
	stub.url = "http://" + listener.Addr().String()
	return stub
}

func putSet(stub *txStub, eventType string, subID map[string]any, extra map[string]any, key *rsa.PrivateKey, aud, iss string) string {
	if key == nil {
		key = txKey
	}
	if aud == "" {
		aud = "my-app"
	}
	if iss == "" {
		iss = stub.url
	}
	jti := strings.TrimPrefix(newID(), "_")
	event := map[string]any{"event_timestamp": 1}
	for k, v := range extra {
		event[k] = v
	}
	token := signJWS(map[string]any{
		"iss": iss, "aud": aud, "jti": jti, "iat": 1, "sub_id": subID, "events": map[string]any{eventType: event},
	}, key, nil)
	stub.mu.Lock()
	stub.queue[jti] = token
	stub.mu.Unlock()
	return jti
}

func loginOf(person, session string) *SamlLogin {
	return &SamlLogin{
		NameID:       person,
		SessionIndex: session,
		Attributes: map[string][]string{
			DefaultSubjectAttribute:             {"urn:uuid:" + person},
			"urn:oid:0.9.2342.19200300.100.1.3": {person + "@example.com"},
		},
	}
}

type quietLog struct{}

func (quietLog) Info(string)  {}
func (quietLog) Warn(string)  {}
func (quietLog) Error(string) {}

func TestVerifiesASetAgainstTheJwks(t *testing.T) {
	jwk := jwkOf(txKey, "k1")
	_, payload, err := VerifyCompactJWS(signJWS(map[string]any{"a": float64(1)}, txKey, nil), []map[string]any{jwk})
	if err != nil || payload["a"] != float64(1) {
		t.Fatal(err, payload)
	}
	rejects(t, func() error {
		_, _, err := VerifyCompactJWS(signJWS(map[string]any{"a": 1}, otherKey, nil), []map[string]any{jwk})
		return err
	}, "signature", "does not verify")
	rejects(t, func() error {
		_, _, err := VerifyCompactJWS(signJWS(map[string]any{"a": 1}, txKey, map[string]any{"alg": "RS256", "kid": "nope"}), []map[string]any{jwk})
		return err
	}, "signature", "no RSA signing key with kid nope")
	rejects(t, func() error {
		_, _, err := VerifyCompactJWS(signJWS(map[string]any{"a": 1}, txKey, map[string]any{"alg": "none"}), []map[string]any{jwk})
		return err
	}, "signature", "does not verify")
	rejects(t, func() error {
		_, _, err := VerifyCompactJWS(signJWS(map[string]any{"a": 1}, txKey, map[string]any{"alg": "HS256", "kid": "k1"}), []map[string]any{jwk})
		return err
	}, "signature", "does not verify")
}

func TestReadsComplexIssSubAndEmailSubjects(t *testing.T) {
	got := SubjectOf(map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
		"session": map[string]any{"format": "opaque", "id": "S1"},
	}, "https://i")
	if got["person"] != "urn:uuid:a" || got["idp_session"] != "S1" {
		t.Fatal(got)
	}
	if len(SubjectOf(map[string]any{"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i")) != 0 {
		t.Fatal("foreign iss")
	}
	email := SubjectOf(map[string]any{"format": "email", "email": "A@x.com"}, "https://i")
	if email["email"] != "A@x.com" {
		t.Fatal(email)
	}
}

func TestNamesAllEightCaepAndFourteenRiscEventTypes(t *testing.T) {
	if len(CAEPEvents()) != 8 || len(RISCEvents()) != 14 {
		t.Fatalf("caep %d risc %d", len(CAEPEvents()), len(RISCEvents()))
	}
	if !contains(CAEPEvents(), Event["risk_level_change"]) || !contains(RISCEvents(), Event["opt_out_effective"]) {
		t.Fatal("missing event")
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestSharedSignals(t *testing.T) {
	stub := startTransmitter(t)
	defer stub.close()
	t.Run("creates its poll stream once and acknowledges", func(t *testing.T) {
		var ended [][]string
		var seen []*SignalEvent
		receiver, err := NewSignalsReceiver(ReceiverOptions{
			Transmitter: stub.url, PollIntervalMS: 60000, Log: quietLog{},
			OnEndSessions: func(ids []string, event *SignalEvent) error {
				ended = append(ended, append([]string{}, ids...))
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		receiver.On("*", func(event *SignalEvent) error { seen = append(seen, event); return nil })
		if err := receiver.Start(); err != nil {
			t.Fatal(err)
		}
		receiver.Stop()
		if stub.created != 1 || stringOf(receiver.Stream["stream_id"]) != "s1" {
			t.Fatalf("created %d stream %v", stub.created, receiver.Stream)
		}
		receiver.Track("L-a1", loginOf("alice", "IDP-A1"), nil)
		receiver.Track("L-a2", loginOf("alice", "IDP-A2"), nil)
		receiver.Track("L-b1", loginOf("bob", "IDP-B1"), nil)
		j1 := putSet(stub, Event["session_revoked"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": map[string]any{"format": "opaque", "id": "IDP-A1"}}, nil, nil, "", "")
		j2 := putSet(stub, Event["credential_change"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}}, map[string]any{"credential_type": "password", "change_type": "update"}, nil, "", "")
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if len(ended) != 1 || strings.Join(ended[0], ",") != "L-a1" {
			t.Fatalf("ended %#v", ended)
		}
		var found *SignalEvent
		for _, event := range seen {
			if event.JTI == j2 {
				found = event
			}
		}
		if found == nil || found.Ended || strings.Join(found.Sessions, ",") != "L-b1" {
			t.Fatalf("found %+v", found)
		}
		j3 := putSet(stub, Event["account_disabled"], map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, nil, nil, "", "")
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if len(ended) != 2 || strings.Join(ended[1], ",") != "L-a2" {
			t.Fatalf("ended %#v", ended)
		}
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if !contains(stub.acked, j1) || !contains(stub.acked, j2) {
			t.Fatalf("acked %v", stub.acked)
		}
		putSet(stub, Event["credential_compromise"], map[string]any{"format": "email", "email": "BOB@example.com"}, map[string]any{"credential_type": "password"}, nil, "", "")
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(ended[2], ",") != "L-b1" {
			t.Fatalf("ended %#v", ended)
		}
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if !contains(stub.acked, j3) {
			t.Fatalf("acked %v missing %s", stub.acked, j3)
		}
		again, err := NewSignalsReceiver(ReceiverOptions{Transmitter: stub.url, Log: quietLog{}, OnEndSessions: func([]string, *SignalEvent) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		if err := again.Start(); err != nil {
			t.Fatal(err)
		}
		again.Stop()
		if stub.created != 1 || stringOf(again.Stream["stream_id"]) != "s1" {
			t.Fatalf("reused created %d %v", stub.created, again.Stream["stream_id"])
		}
		_ = j1
	})

	t.Run("refuses a forged misaddressed or foreign set", func(t *testing.T) {
		var ended [][]string
		index := NewMemorySessionIndex(0)
		receiver, err := NewSignalsReceiver(ReceiverOptions{
			Transmitter: stub.url, SessionIndex: index, Log: quietLog{},
			OnEndSessions: func(ids []string, event *SignalEvent) error {
				ended = append(ended, ids)
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := receiver.Start(); err != nil {
			t.Fatal(err)
		}
		receiver.Stop()
		receiver.Track("L-c1", loginOf("carol", "IDP-C1"), nil)
		subject := map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}, "session": map[string]any{"format": "opaque", "id": "IDP-C1"}}
		forged := putSet(stub, Event["session_revoked"], subject, nil, otherKey, "", "")
		mis := putSet(stub, Event["session_revoked"], subject, nil, nil, "someone-else", "")
		foreign := putSet(stub, Event["session_revoked"], subject, nil, nil, "", "https://evil.example")
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		if len(ended) != 0 || strings.Join(index.ByPerson("urn:uuid:carol"), ",") != "L-c1" {
			t.Fatalf("ended %v sessions %v", ended, index.ByPerson("urn:uuid:carol"))
		}
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		for _, jti := range []string{forged, mis, foreign} {
			if _, ok := stub.errs[jti]; !ok {
				t.Fatalf("missing err %s in %v", jti, stub.errs)
			}
		}
	})

	t.Run("acknowledges a valid set whose handler throws", func(t *testing.T) {
		var errorsLog []string
		var seen []string
		receiver, err := NewSignalsReceiver(ReceiverOptions{
			Transmitter: stub.url, Log: collectingLog{errors: &errorsLog},
			OnEndSessions: func([]string, *SignalEvent) error { return errCode("ssf", "store down") },
		})
		if err != nil {
			t.Fatal(err)
		}
		receiver.On(Event["credential_change"], func(*SignalEvent) error { return errCode("ssf", "handler bug") })
		receiver.On("*", func(event *SignalEvent) error { seen = append(seen, event.JTI); return nil })
		if err := receiver.Start(); err != nil {
			t.Fatal(err)
		}
		receiver.Stop()
		receiver.Track("L-d1", loginOf("dave", "IDP-D1"), nil)
		j1 := putSet(stub, Event["credential_change"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}}, map[string]any{"credential_type": "password", "change_type": "update"}, nil, "", "")
		j2 := putSet(stub, Event["session_revoked"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}, "session": map[string]any{"format": "opaque", "id": "IDP-D1"}}, nil, nil, "", "")
		for i := 0; i < 3; i++ {
			if _, err := receiver.PollOnce(); err != nil {
				t.Fatal(err)
			}
		}
		if !contains(stub.acked, j1) || !contains(stub.acked, j2) {
			t.Fatalf("acked %v", stub.acked)
		}
		if _, ok := stub.errs[j1]; ok {
			t.Fatal("j1 erred")
		}
		if _, ok := stub.errs[j2]; ok {
			t.Fatal("j2 erred")
		}
		sort.Strings(seen)
		want := []string{j1, j2}
		sort.Strings(want)
		if strings.Join(seen, ",") != strings.Join(want, ",") {
			t.Fatalf("seen %v", seen)
		}
		handler := false
		ended := false
		for _, message := range errorsLog {
			if regexp.MustCompile(`handler for .*credential-change threw`).MatchString(message) {
				handler = true
			}
			if strings.Contains(message, "onEndSessions threw") {
				ended = true
			}
		}
		if !handler || !ended {
			t.Fatalf("logs %v", errorsLog)
		}
	})

	t.Run("never runs two polls at once", func(t *testing.T) {
		var seen []string
		var mu sync.Mutex
		receiver, err := NewSignalsReceiver(ReceiverOptions{Transmitter: stub.url, Log: quietLog{}, OnEndSessions: func([]string, *SignalEvent) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		receiver.On("*", func(event *SignalEvent) error {
			mu.Lock()
			seen = append(seen, event.JTI)
			mu.Unlock()
			return nil
		})
		if err := receiver.Start(); err != nil {
			t.Fatal(err)
		}
		receiver.Stop()
		jti := putSet(stub, Event["account_enabled"], map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:erin"}, nil, nil, "", "")
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = receiver.PollOnce()
			}()
		}
		wg.Wait()
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, item := range seen {
			if item == jti {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("handled %d times %v", count, seen)
		}
	})
}

type collectingLog struct{ errors *[]string }

func (collectingLog) Info(string) {}
func (collectingLog) Warn(string) {}
func (c collectingLog) Error(message string) {
	*c.errors = append(*c.errors, message)
}

func TestRefusesATransmitterWithoutPollDelivery(t *testing.T) {
	receiver, err := NewSignalsReceiver(ReceiverOptions{Transmitter: "http://127.0.0.1:1", Log: quietLog{}, OnEndSessions: func([]string, *SignalEvent) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	err = receiver.Start()
	var samlErr *SamlError
	if !errorsAs(err, &samlErr) || samlErr.Code != "ssf" {
		t.Fatal(err)
	}
}

func TestStopWaitsForAnInFlightPoll(t *testing.T) {
	stub := startTransmitter(t)
	defer stub.close()
	stub.hold = make(chan struct{})
	stub.entered = make(chan struct{})
	receiver, err := NewSignalsReceiver(ReceiverOptions{Transmitter: stub.url, PollIntervalMS: 60000, Log: quietLog{}, OnEndSessions: func([]string, *SignalEvent) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- receiver.Start() }()
	select {
	case <-stub.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not start")
	}
	stopped := make(chan struct{})
	go func() {
		receiver.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop returned before the poll finished")
	case <-time.After(150 * time.Millisecond):
	}
	close(stub.hold)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return")
	}
	if err := <-started; err != nil {
		t.Fatal(err)
	}
}
