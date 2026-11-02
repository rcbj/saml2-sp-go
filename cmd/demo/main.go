// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rcbj/saml2-sp-go"
)

const sessionMS = 8 * time.Hour

var (
	port           = 3000
	publicURL      string
	publicGiven    bool
	configPath     string
	secret         []byte
	secureCookies  = true
	signalsOff     bool
	ssfTransmitter string
	ssfPollMS      int
	receiver       *saml.SignalsReceiver
	receiverState  = "not configured (no ssf block in the configuration file)"
	spOnce         sync.Once
	spValue        *saml.ServiceProvider
	spErr          error
	sessionsMu     sync.Mutex
	sessions       = map[string]*held{}
	eventsMu       sync.Mutex
	events         []seen
)

const sessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

// seen is one accepted Shared Signals event, as GET /live-status reports it.
type seen struct {
	Type string `json:"type"`
	JTI  string `json:"jti"`
}

type held struct {
	login   *saml.SamlLogin
	expires time.Time
}

func main() {
	if err := configure(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", route)
	server := &http.Server{Addr: "0.0.0.0:" + strconv.Itoa(port), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Printf("saml2-sp demo on port %d, configuration %s\n", port, configPath)
	go func() { _ = server.Serve(listener) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	if receiver != nil {
		receiver.Stop()
	}
	_ = server.Close()
}

func configure(argv []string) error {
	if raw := os.Getenv("PORT"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("PORT is not a port")
		}
		port = n
	}
	publicURL = strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	publicGiven = os.Getenv("PUBLIC_URL") != ""
	configPath = os.Getenv("SAML_CONFIG")
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--public-url":
			if i+1 >= len(argv) {
				return fmt.Errorf("--public-url needs a value")
			}
			i++
			publicURL = strings.TrimRight(argv[i], "/")
			publicGiven = true
		case "--config":
			if i+1 >= len(argv) {
				return fmt.Errorf("--config needs a value")
			}
			i++
			configPath = argv[i]
		default:
			return fmt.Errorf("Unknown argument %s", argv[i])
		}
	}
	if publicGiven && publicURL == "" {
		return fmt.Errorf("--public-url is empty")
	}
	if configPath == "" {
		configPath = "demo/saml.json"
	}
	if !filepath.IsAbs(configPath) {
		configPath, _ = filepath.Abs(configPath)
	}
	if raw := os.Getenv("SESSION_SECRET"); raw != "" {
		secret = []byte(raw)
	} else {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	file := readFile()
	if file["signals"] == false {
		signalsOff = true
		receiverState = "not configured (signals are off)"
	}
	if ssf, ok := file["ssf"].(map[string]any); ok && !signalsOff {
		ssfTransmitter, _ = ssf["transmitter"].(string)
		if n, ok := ssf["pollIntervalMs"].(float64); ok {
			ssfPollMS = int(n)
		}
	}
	if signalsOff || ssfTransmitter == "" {
		if !signalsOff && ssfTransmitter == "" {
			receiverState = "not configured (no ssf block in the configuration file)"
		}
	}
	secureCookies = secureFrom(portOverrides())
	return nil
}

func readFile() map[string]any {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return map[string]any{}
	}
	var parsed any
	if json.Unmarshal(raw, &parsed) != nil {
		return map[string]any{}
	}
	obj, _ := parsed.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	return obj
}

func portOverrides() map[string]any {
	file := readFile()
	entity, _ := file["entityId"].(string)
	acs, _ := file["acsUrl"].(string)
	if entity == "" || acs == "" {
		return map[string]any{}
	}
	entity, acs = endpoints(entity, acs)
	return map[string]any{"entityId": entity, "acsUrl": acs}
}

func endpoints(entity, acs string) (string, string) {
	if publicGiven && publicURL != "" {
		return replaceOrigin(entity, publicURL), replaceOrigin(acs, publicURL)
	}
	return onPort(entity, port), onPort(acs, port)
}

func replaceOrigin(value, public string) string {
	base, err := url.Parse(public)
	if err != nil {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.Scheme = base.Scheme
	parsed.Host = base.Host
	return parsed.String()
}

func onPort(raw string, number int) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := parsed.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return raw
	}
	if strings.Contains(host, ":") {
		parsed.Host = fmt.Sprintf("[%s]:%d", host, number)
	} else {
		parsed.Host = fmt.Sprintf("%s:%d", host, number)
	}
	return parsed.String()
}

func secureFrom(overrides map[string]any) bool {
	acs, _ := overrides["acsUrl"].(string)
	if acs == "" {
		acs = fmt.Sprintf("http://localhost:%d/", port)
	}
	parsed, err := url.Parse(acs)
	if err != nil {
		return true
	}
	return parsed.Scheme == "https" || parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
}

func provider() (*saml.ServiceProvider, error) {
	spOnce.Do(func() {
		spValue, spErr = saml.FromFile(configPath, portOverrides(), nil)
		if spErr != nil {
			return
		}
		startReceiver(spValue)
	})
	return spValue, spErr
}

func startReceiver(sp *saml.ServiceProvider) {
	if sp.Config.Signals != nil && !*sp.Config.Signals {
		receiverState = "not configured (signals are off)"
		return
	}
	if ssfTransmitter == "" || receiver != nil {
		return
	}
	tls := &saml.TLSOptions{Cert: sp.Config.CertificatePEM, Key: sp.Config.PrivateKeyPEM}
	if sp.Config.IdpCA != "" {
		tls.CA = sp.Config.IdpCA
	}
	built, err := saml.NewSignalsReceiver(saml.ReceiverOptions{
		Transmitter:    ssfTransmitter,
		TLS:            tls,
		Description:    "saml2-sp demo (" + sp.Config.EntityID + ")",
		PollIntervalMS: ssfPollMS,
		OnEndSessions: func(ids []string, event *saml.SignalEvent) error {
			sessionsMu.Lock()
			defer sessionsMu.Unlock()
			for _, id := range ids {
				delete(sessions, id)
			}
			fmt.Printf("ssf: ended %d local session(s)\n", len(ids))
			return nil
		},
	})
	if err != nil {
		receiverState = "not running: " + err.Error()
		return
	}
	built.On("*", func(event *saml.SignalEvent) error {
		eventsMu.Lock()
		events = append(events, seen{Type: event.Type, JTI: event.JTI})
		eventsMu.Unlock()
		// The assertion SessionIndex may be the assertion id rather than the
		// sign-on session the CAEP event names, so nothing matched. This demo
		// then ends its one local session. Demo code, not the library.
		if event.Type != sessionRevoked || event.Ended {
			return nil
		}
		sessionsMu.Lock()
		if len(sessions) != 1 {
			sessionsMu.Unlock()
			return nil
		}
		var sid string
		for id := range sessions {
			sid = id
		}
		delete(sessions, sid)
		sessionsMu.Unlock()
		built.Untrack(sid)
		fmt.Println("ssf: the assertion SessionIndex is not the CAEP session id; ended this demo's one session")
		return nil
	})
	receiver = built
	go func() {
		if err := built.Start(); err != nil {
			receiverState = "not running: " + err.Error()
			fmt.Printf("ssf: the receiver did not start: %s\n", err.Error())
			if receiver == built {
				receiver = nil
			}
			return
		}
		receiverState = fmt.Sprintf("polling stream %s at %s", stringOf(built.Stream["stream_id"]), ssfTransmitter)
	}()
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}

func route(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		return
	}
	if r.URL.Path == "/live-status" && r.Method == http.MethodGet {
		liveStatus(w)
		return
	}
	switch r.URL.Path {
	case "/styles.css":
		http.ServeFile(w, r, "demo/public/styles.css")
		return
	case "/app.js":
		http.ServeFile(w, r, "demo/public/app.js")
		return
	case "/saml/metadata":
		sp, err := provider()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/samlmetadata+xml")
		_, _ = io.WriteString(w, sp.Metadata())
		return
	case "/login":
		if r.Method == http.MethodGet {
			login(w, r)
			return
		}
	case "/saml/acs":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			acs(w, r)
			return
		}
	case "/logout":
		if r.Method == http.MethodPost {
			logout(w, r)
			return
		}
	case "/":
		if r.Method == http.MethodGet {
			page(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// liveStatus answers the live test: signed in or not, the subject, the
// receiver state, and each accepted event's type and jti. Never an assertion.
func liveStatus(w http.ResponseWriter) {
	now := time.Now()
	signedIn := false
	var subject any
	sessionsMu.Lock()
	for _, item := range sessions {
		if now.After(item.expires) {
			continue
		}
		signedIn = true
		if subject == nil && item.login.NameID != "" {
			subject = item.login.NameID
		}
	}
	sessionsMu.Unlock()
	eventsMu.Lock()
	list := append([]seen{}, events...)
	eventsMu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"signedIn": signedIn, "subject": subject, "receiver": receiverState, "events": list,
	})
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_, _ = w.Write(body)
}

func page(w http.ResponseWriter, r *http.Request) {
	var problem string
	sp, err := provider()
	if err != nil {
		problem = "The service provider is not configured yet: " + err.Error() + ". Run the setup script (python scripts/configure_iya_sts.py)."
	}
	_ = sp
	current := currentSession(r)
	body := `<h1>SAML service provider</h1>`
	if problem != "" && current == nil {
		body += `<p class="problem">` + html.EscapeString(problem) + `</p>`
	}
	body += `<p>Shared Signals: ` + html.EscapeString(receiverState) + `</p>`
	if current != nil {
		body += `<p>Signed in as <strong>` + html.EscapeString(current.login.NameID) + `</strong> (` + html.EscapeString(current.login.Binding) + `).</p>`
		body += `<form method="post" action="/logout"><button type="submit">Log out</button></form>`
	} else if problem == "" {
		body += `<p><a href="/login">Sign in</a></p>`
	}
	writePage(w, "saml2-sp", body, http.StatusOK)
}

func login(w http.ResponseWriter, r *http.Request) {
	sp, err := provider()
	if err != nil {
		writePage(w, "Sign-in", `<h1>Sign-in is not available</h1><p class="problem">`+html.EscapeString(err.Error())+`</p>`, http.StatusInternalServerError)
		return
	}
	asked := r.URL.Query().Get("binding")
	responseBinding := ""
	if asked == "post" || asked == "redirect" || asked == "artifact" {
		responseBinding = asked
	}
	nonce := base64.RawURLEncoding.EncodeToString(random(16))
	relay := "/"
	req, err := sp.Login(saml.LoginOptions{RelayState: &relay, Nonce: nonce, ResponseBinding: responseBinding})
	if err != nil {
		writePage(w, "Sign-in", `<h1>Sign-in failed</h1><p class="problem">`+html.EscapeString(err.Error())+`</p>`, http.StatusBadRequest)
		return
	}
	pending := map[string]any{"ids": []string{req.ID}}
	http.SetCookie(w, makeCookie("saml_pending", seal(pending), acsPath(sp), 600, "None"))
	if req.Binding == "redirect" {
		w.Header().Set("referrer-policy", "no-referrer")
		http.Redirect(w, r, req.URL, http.StatusFound)
		return
	}
	origin, _ := url.Parse(req.URL)
	w.Header().Set("content-security-policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; form-action %s://%s; frame-ancestors 'none'; base-uri 'none'", nonce, origin.Scheme, origin.Host))
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, req.HTML)
}

func acs(w http.ResponseWriter, r *http.Request) {
	sp, err := provider()
	if err != nil {
		writePage(w, "Sign-in failed", `<h1>Sign-in failed</h1><p class="problem">`+html.EscapeString(err.Error())+`</p>`, http.StatusBadRequest)
		return
	}
	var body any
	if r.Method == http.MethodPost {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024))
		body = string(raw)
	}
	pending := unseal(cookieValue(r, "saml_pending"))
	var ids []string
	if list, ok := pending["ids"].([]any); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				ids = append(ids, text)
			}
		}
	}
	login, err := sp.Acs(r.Method, r.URL.RequestURI(), body, ids)
	clear := makeCookie("saml_pending", "", acsPath(sp), 0, "None")
	if err != nil {
		http.SetCookie(w, clear)
		writePage(w, "Sign-in failed", `<h1>Sign-in failed</h1><p class="problem">`+html.EscapeString(err.Error())+`</p><p><a href="/">Start again</a></p>`, http.StatusBadRequest)
		return
	}
	sid := base64.RawURLEncoding.EncodeToString(random(32))
	until := time.Now().Add(sessionMS)
	if login.SessionNotOnOrAfter != nil && login.SessionNotOnOrAfter.Before(until) {
		until = *login.SessionNotOnOrAfter
	}
	sessionsMu.Lock()
	sessions[sid] = &held{login: login, expires: until}
	sessionsMu.Unlock()
	if receiver != nil {
		receiver.Track(sid, login, &until)
	}
	fmt.Printf("signed in %s by %s (assertion %s)\n", login.NameID, login.Binding, login.AssertionID)
	http.SetCookie(w, clear)
	http.SetCookie(w, makeCookie("sid", sid, "/", int(time.Until(until).Seconds()), "Lax"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if sid := cookieValue(r, "sid"); sid != "" {
		sessionsMu.Lock()
		delete(sessions, sid)
		sessionsMu.Unlock()
		if receiver != nil {
			receiver.Untrack(sid)
		}
	}
	http.SetCookie(w, makeCookie("sid", "", "/", 0, "Lax"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func currentSession(r *http.Request) *held {
	sid := cookieValue(r, "sid")
	if sid == "" {
		return nil
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	found := sessions[sid]
	if found == nil || time.Now().After(found.expires) {
		delete(sessions, sid)
		return nil
	}
	return found
}

func acsPath(sp *saml.ServiceProvider) string {
	parsed, err := url.Parse(sp.Config.AcsURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func makeCookie(name, value, path string, maxAge int, sameSite string) *http.Cookie {
	site := http.SameSiteLaxMode
	if sameSite == "None" {
		site = http.SameSiteNoneMode
	}
	return &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge, HttpOnly: true, Secure: secureCookies, SameSite: site,
	}
}

func seal(value map[string]any) string {
	raw, _ := json.Marshal(value)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unseal(value string) map[string]any {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func random(n int) []byte {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return buf
}

func writePage(w http.ResponseWriter, title, body string, status int) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>"+html.EscapeString(title)+"</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body>"+body+"</body></html>")
}
