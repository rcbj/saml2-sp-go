// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const pollMethod = "urn:ietf:rfc:8936"

// Logger receives the receiver's operational messages.
type Logger interface {
	Info(message string)
	Warn(message string)
	Error(message string)
}

type printLogger struct{}

func (printLogger) Info(message string)  { fmt.Println(message) }
func (printLogger) Warn(message string)  { fmt.Println(message) }
func (printLogger) Error(message string) { fmt.Println(message) }

// SignalEvent is one event inside a Security Event Token.
type SignalEvent struct {
	Type     string
	Payload  map[string]any
	Subject  map[string]string
	JTI      string
	Sessions []string
	Ended    bool
	Iat      any
	Txn      *string
}

// ReceiverOptions configures a Shared Signals poll receiver.
type ReceiverOptions struct {
	Transmitter      string
	OnEndSessions    func(ids []string, event *SignalEvent) error
	TLS              *TLSOptions
	Headers          func() map[string]string
	EventsRequested  []string
	EndOn            []string
	SessionIndex     *MemorySessionIndex
	SubjectAttribute string
	Description      string
	PollIntervalMS   int
	MaxEvents        int
	Log              Logger
}

type flight struct {
	done   chan struct{}
	result bool
	err    error
}

// SignalsReceiver polls one RFC 8936 stream of CAEP and RISC events.
type SignalsReceiver struct {
	transmitter      string
	onEnd            func(ids []string, event *SignalEvent) error
	tls              *TLSOptions
	headers          func() map[string]string
	eventsRequested  []string
	endOn            map[string]bool
	index            *MemorySessionIndex
	subjectAttribute string
	description      string
	pollInterval     time.Duration
	maxEvents        int
	log              Logger

	mu       sync.Mutex
	config   map[string]any
	Stream   map[string]any
	keys     []map[string]any
	keysAt   time.Time
	ack      []string
	errs     map[string]map[string]string
	handlers map[string][]func(*SignalEvent) error

	sched    sync.Mutex
	running  bool
	timer    *time.Timer
	inflight *flight
	wg       sync.WaitGroup
}

// NewSignalsReceiver builds a receiver. It does not contact the transmitter until Start.
func NewSignalsReceiver(opt ReceiverOptions) (*SignalsReceiver, error) {
	if opt.OnEndSessions == nil {
		return nil, errCode("config", "onEndSessions is required")
	}
	if !strings.HasPrefix(opt.Transmitter, "http://") && !strings.HasPrefix(opt.Transmitter, "https://") {
		return nil, errCode("config", "transmitter must be an http(s) URL")
	}
	interval := opt.PollIntervalMS
	if interval <= 0 {
		interval = 5000
	}
	maxEvents := opt.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 50
	}
	requested := opt.EventsRequested
	if requested == nil {
		requested = DefaultEventsRequested()
	}
	ending := opt.EndOn
	if ending == nil {
		ending = DefaultEndingEvents()
	}
	endOn := map[string]bool{}
	for _, item := range ending {
		endOn[item] = true
	}
	index := opt.SessionIndex
	if index == nil {
		index = NewMemorySessionIndex(0)
	}
	log := opt.Log
	if log == nil {
		log = printLogger{}
	}
	return &SignalsReceiver{
		transmitter:      strings.TrimRight(opt.Transmitter, "/"),
		onEnd:            opt.OnEndSessions,
		tls:              opt.TLS,
		headers:          opt.Headers,
		eventsRequested:  append([]string{}, requested...),
		endOn:            endOn,
		index:            index,
		subjectAttribute: opt.SubjectAttribute,
		description:      opt.Description,
		pollInterval:     time.Duration(interval) * time.Millisecond,
		maxEvents:        maxEvents,
		log:              log,
		errs:             map[string]map[string]string{},
		handlers:         map[string][]func(*SignalEvent) error{},
	}, nil
}

// Track remembers a local session so a later event can end it.
func (r *SignalsReceiver) Track(localID string, login *SamlLogin, expiresAt *time.Time) {
	r.index.Add(TrackedFrom(localID, login, r.subjectAttribute, expiresAt))
}

// Untrack forgets a local session.
func (r *SignalsReceiver) Untrack(localID string) {
	r.index.Remove(localID)
}

// On registers a handler for one event type, or "*" for every type.
func (r *SignalsReceiver) On(eventType string, handler func(*SignalEvent) error) *SignalsReceiver {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[eventType] = append(r.handlers[eventType], handler)
	return r
}

func (r *SignalsReceiver) call(method, rawURL string, body any, hasBody bool) (int, any, error) {
	headers := map[string]string{"accept": "application/json"}
	if r.headers != nil {
		for key, value := range r.headers() {
			headers[key] = value
		}
	}
	payload := ""
	if hasBody {
		headers["content-type"] = "application/json"
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, errCause("ssf", err.Error(), err)
		}
		payload = string(raw)
	}
	answer, err := send(rawURL, method, headers, payload, r.tls, "ssf")
	if err != nil {
		return 0, nil, err
	}
	var parsed any
	if answer.Body != "" {
		if err := json.Unmarshal([]byte(answer.Body), &parsed); err != nil {
			parsed = answer.Body
		}
	}
	return answer.Status, parsed, nil
}

func (r *SignalsReceiver) discover() (map[string]any, error) {
	url := r.transmitter + "/.well-known/ssf-configuration"
	status, parsed, err := r.call("GET", url, nil, false)
	if err != nil {
		return nil, err
	}
	config, _ := parsed.(map[string]any)
	if status != 200 || config == nil || stringOf(config["configuration_endpoint"]) == "" || stringOf(config["jwks_uri"]) == "" {
		return nil, errCode("ssf", fmt.Sprintf("%s answered %d without a usable transmitter configuration", url, status))
	}
	if supported, ok := config["delivery_methods_supported"].([]any); ok && len(supported) > 0 {
		found := false
		for _, item := range supported {
			if stringOf(item) == pollMethod {
				found = true
			}
		}
		if !found {
			return nil, errCode("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
		}
	}
	return config, nil
}

func (r *SignalsReceiver) jwks(force bool) ([]map[string]any, error) {
	r.mu.Lock()
	if !force && len(r.keys) > 0 && time.Since(r.keysAt) < time.Hour {
		keys := r.keys
		r.mu.Unlock()
		return keys, nil
	}
	uri := stringOf(r.config["jwks_uri"])
	r.mu.Unlock()
	status, parsed, err := r.call("GET", uri, nil, false)
	if err != nil {
		return nil, err
	}
	obj, _ := parsed.(map[string]any)
	raw, _ := obj["keys"].([]any)
	if status != 200 || raw == nil {
		return nil, errCode("ssf", fmt.Sprintf("the transmitter's JWKS answered %d", status))
	}
	keys := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if key, ok := item.(map[string]any); ok {
			keys = append(keys, key)
		}
	}
	r.mu.Lock()
	r.keys = keys
	r.keysAt = time.Now()
	r.mu.Unlock()
	return keys, nil
}

func (r *SignalsReceiver) ensureStream() (map[string]any, error) {
	endpoint := stringOf(r.config["configuration_endpoint"])
	status, parsed, err := r.call("GET", endpoint, nil, false)
	if err != nil {
		return nil, err
	}
	if status == 200 {
		var all []any
		switch typed := parsed.(type) {
		case []any:
			all = typed
		case map[string]any:
			if typed != nil {
				all = []any{typed}
			}
		}
		for _, item := range all {
			stream, ok := item.(map[string]any)
			if !ok || stringOf(stream["stream_id"]) == "" {
				continue
			}
			delivery, _ := stream["delivery"].(map[string]any)
			if stringOf(delivery["method"]) == pollMethod {
				return stream, nil
			}
		}
	} else if status != 404 {
		raw, _ := json.Marshal(parsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return nil, errCode("ssf", fmt.Sprintf("listing the streams at %s answered %d: %s", endpoint, status, text))
	}
	body := map[string]any{
		"delivery":         map[string]any{"method": pollMethod},
		"events_requested": r.eventsRequested,
	}
	if r.description != "" {
		body["description"] = r.description
	}
	createdStatus, createdParsed, err := r.call("POST", endpoint, body, true)
	if err != nil {
		return nil, err
	}
	stream, _ := createdParsed.(map[string]any)
	if (createdStatus != 200 && createdStatus != 201) || stream == nil || stringOf(stream["stream_id"]) == "" {
		raw, _ := json.Marshal(createdParsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return nil, errCode("ssf", fmt.Sprintf("creating a stream at %s answered %d: %s", endpoint, createdStatus, text))
	}
	return stream, nil
}

// Start discovers the transmitter, ensures one poll stream, and polls once before returning.
func (r *SignalsReceiver) Start() error {
	r.sched.Lock()
	if r.running {
		r.sched.Unlock()
		return nil
	}
	r.sched.Unlock()
	config, err := r.discover()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = config
	r.mu.Unlock()
	if _, err := r.jwks(true); err != nil {
		return err
	}
	stream, err := r.ensureStream()
	if err != nil {
		return err
	}
	delivery, _ := stream["delivery"].(map[string]any)
	if stringOf(delivery["endpoint_url"]) == "" {
		return errCode("ssf", "the stream has no poll endpoint_url")
	}
	r.sched.Lock()
	if r.running {
		r.sched.Unlock()
		return nil
	}
	r.mu.Lock()
	r.Stream = stream
	r.mu.Unlock()
	r.running = true
	r.sched.Unlock()
	delivered, _ := stream["events_delivered"].([]any)
	r.log.Info(fmt.Sprintf("ssf: polling stream %s at %s, delivering %d event type(s)", stringOf(stream["stream_id"]), stringOf(delivery["endpoint_url"]), len(delivered)))
	r.iteration()
	return nil
}

// Stop cancels the next poll and waits until a poll already running has finished.
func (r *SignalsReceiver) Stop() {
	r.sched.Lock()
	r.running = false
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.sched.Unlock()
	r.wg.Wait()
}

func (r *SignalsReceiver) iteration() {
	r.sched.Lock()
	if !r.running {
		r.sched.Unlock()
		return
	}
	r.wg.Add(1)
	r.sched.Unlock()
	defer r.wg.Done()
	delay := r.pollInterval
	if more, err := r.PollOnce(); err != nil {
		r.log.Warn("ssf: poll failed: " + err.Error())
		delay = r.pollInterval * 4
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
	} else if more {
		delay = 0
	}
	r.sched.Lock()
	defer r.sched.Unlock()
	if !r.running {
		return
	}
	r.timer = time.AfterFunc(delay, r.iteration)
}

// PollOnce fetches one batch. Concurrent callers share that single request.
func (r *SignalsReceiver) PollOnce() (bool, error) {
	r.sched.Lock()
	if r.inflight != nil {
		current := r.inflight
		r.sched.Unlock()
		<-current.done
		return current.result, current.err
	}
	current := &flight{done: make(chan struct{})}
	r.inflight = current
	r.sched.Unlock()
	result, err := r.pollNow()
	current.result = result
	current.err = err
	r.sched.Lock()
	r.inflight = nil
	close(current.done)
	r.sched.Unlock()
	return result, err
}

func (r *SignalsReceiver) pollNow() (bool, error) {
	r.mu.Lock()
	delivery, _ := r.Stream["delivery"].(map[string]any)
	url := stringOf(delivery["endpoint_url"])
	ack := r.ack
	r.ack = nil
	setErrs := r.errs
	r.errs = map[string]map[string]string{}
	r.mu.Unlock()
	body := map[string]any{"maxEvents": r.maxEvents, "returnImmediately": true}
	if len(ack) > 0 {
		body["ack"] = ack
	}
	if len(setErrs) > 0 {
		body["setErrs"] = setErrs
	}
	status, parsed, err := r.call("POST", url, body, true)
	if err != nil || status != 200 {
		r.mu.Lock()
		r.ack = append(append([]string{}, ack...), r.ack...)
		merged := map[string]map[string]string{}
		for key, value := range setErrs {
			merged[key] = value
		}
		for key, value := range r.errs {
			merged[key] = value
		}
		r.errs = merged
		r.mu.Unlock()
		if err != nil {
			return false, err
		}
		raw, _ := json.Marshal(parsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return false, errCode("ssf", fmt.Sprintf("the poll answered %d: %s", status, text))
	}
	payload, _ := parsed.(map[string]any)
	sets, _ := payload["sets"].(map[string]any)
	for jti, token := range sets {
		if err := r.handle(jti, stringOf(token)); err != nil {
			description := err.Error()
			r.log.Warn("ssf: SET " + jti + " refused: " + description)
			kind := "invalid_request"
			if samlErr, ok := err.(*SamlError); ok && samlErr.Code == "signature" {
				kind = "invalid_key"
			}
			r.mu.Lock()
			r.errs[jti] = map[string]string{"err": kind, "description": description}
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.ack = append(r.ack, jti)
		r.mu.Unlock()
	}
	more, _ := payload["moreAvailable"].(bool)
	return more, nil
}

func (r *SignalsReceiver) handle(jti, token string) error {
	keys, err := r.jwks(false)
	if err != nil {
		return err
	}
	header, payload, err := VerifyCompactJWS(token, keys)
	if err != nil {
		if samlErr, ok := err.(*SamlError); ok && (strings.Contains(samlErr.Message, "publishes no") || strings.Contains(samlErr.Message, "does not verify")) {
			keys, refreshErr := r.jwks(true)
			if refreshErr != nil {
				return err
			}
			header, payload, err = VerifyCompactJWS(token, keys)
		}
		if err != nil {
			return err
		}
	}
	if header["typ"] != nil && strings.ToLower(stringOf(header["typ"])) != "secevent+jwt" {
		return errCode("validation", "the SET's typ is "+stringOf(header["typ"]))
	}
	r.mu.Lock()
	issuer := stringOf(r.config["issuer"])
	want := r.Stream["aud"]
	r.mu.Unlock()
	if stringOf(payload["iss"]) != issuer {
		return errCode("validation", fmt.Sprintf("the SET was issued by %s, not %s", stringOf(payload["iss"]), issuer))
	}
	var wanted []string
	switch typed := want.(type) {
	case []any:
		for _, item := range typed {
			wanted = append(wanted, stringOf(item))
		}
	case string:
		if typed != "" {
			wanted = []string{typed}
		}
	}
	var audience []string
	switch typed := payload["aud"].(type) {
	case []any:
		for _, item := range typed {
			audience = append(audience, stringOf(item))
		}
	case string:
		audience = []string{typed}
	case nil:
	default:
		audience = []string{fmt.Sprint(typed)}
	}
	if len(wanted) > 0 {
		match := false
		for _, item := range audience {
			for _, allowed := range wanted {
				if item == allowed {
					match = true
				}
			}
		}
		if !match {
			return errCode("validation", "the SET is for "+strings.Join(audience, ", ")+", not this stream")
		}
	}
	if payload["jti"] != nil && stringOf(payload["jti"]) != jti {
		return errCode("validation", "the SET's jti is not the one it was delivered under")
	}
	events, ok := payload["events"].(map[string]any)
	if !ok || len(events) == 0 {
		return errCode("validation", "the SET carries no events")
	}
	for eventType, rawBody := range events {
		body, _ := rawBody.(map[string]any)
		var subjectSource any
		if payload["sub_id"] != nil {
			subjectSource = payload["sub_id"]
		} else if body != nil {
			subjectSource = body["subject"]
		}
		subject := SubjectOf(subjectSource, issuer)
		sessions := r.sessionsFor(eventType, subject)
		ends := r.endOn[eventType] && len(sessions) > 0
		var iat any
		switch typed := payload["iat"].(type) {
		case float64:
			iat = typed
		case int:
			iat = typed
		}
		var txn *string
		if text, ok := payload["txn"].(string); ok {
			txn = &text
		}
		payloadBody := body
		if payloadBody == nil {
			payloadBody = map[string]any{}
		}
		event := &SignalEvent{
			Type: eventType, Payload: payloadBody, Subject: subject, JTI: jti, Sessions: sessions, Ended: ends, Iat: iat, Txn: txn,
		}
		if ends {
			if err := r.onEnd(sessions, event); err != nil {
				r.log.Error(fmt.Sprintf("ssf: onEndSessions threw for %s (SET %s is still acknowledged): %v", eventType, jti, err))
				event.Ended = false
			}
			if event.Ended {
				for _, localID := range sessions {
					r.index.Remove(localID)
				}
			}
		}
		r.mu.Lock()
		handlers := append(append([]func(*SignalEvent) error{}, r.handlers[eventType]...), r.handlers["*"]...)
		r.mu.Unlock()
		for _, handler := range handlers {
			if err := handler(event); err != nil {
				r.log.Error(fmt.Sprintf("ssf: a handler for %s threw (SET %s is still acknowledged): %v", eventType, jti, err))
			}
		}
	}
	return nil
}

func (r *SignalsReceiver) sessionsFor(eventType string, subject map[string]string) []string {
	if eventType == Event["verification"] || eventType == Event["stream_updated"] {
		return nil
	}
	if subject["idp_session"] != "" {
		found := r.index.ByIdPSession(subject["idp_session"])
		if len(found) > 0 || eventType == Event["session_revoked"] {
			return found
		}
	}
	if subject["person"] != "" {
		return r.index.ByPerson(subject["person"])
	}
	if subject["email"] != "" {
		return r.index.ByEmail(subject["email"])
	}
	return nil
}

// Verify asks the transmitter to deliver a verification event.
func (r *SignalsReceiver) Verify(state string) error {
	r.mu.Lock()
	endpoint := ""
	if r.config != nil {
		endpoint = stringOf(r.config["verification_endpoint"])
	}
	streamID := stringOf(r.Stream["stream_id"])
	r.mu.Unlock()
	if endpoint == "" {
		return errCode("ssf", "the transmitter publishes no verification_endpoint")
	}
	body := map[string]any{"stream_id": streamID}
	if state != "" {
		body["state"] = state
	}
	status, _, err := r.call("POST", endpoint, body, true)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return errCode("ssf", fmt.Sprintf("verification answered %d", status))
	}
	return nil
}
