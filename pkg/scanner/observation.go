package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/verify"
)

const (
	maxPathSamples        = 32
	maxObservationPaths   = 128
	maxObservationSamples = 256
	maxObservationBody    = 256 * 1024
)

type reflectionState string

const (
	reflectionUnknown     reflectionState = "unknown"
	reflectionNotObserved reflectionState = "not_observed"
	reflectionExact       reflectionState = "literal_match"
	reflectionHTMLEncoded reflectionState = "html_encoded_match"
)

type failureCode string

const (
	failureNone      failureCode = ""
	failurePolicy    failureCode = "policy"
	failureBuild     failureCode = "request_build"
	failureWait      failureCode = "rate_wait"
	failureTransport failureCode = "transport"
	failureRead      failureCode = "response_read"
	failureStatus    failureCode = "http_status"
	failureCanceled  failureCode = "canceled"
	failureDeadline  failureCode = "deadline"
)

// One logical candidate may issue retries, redirects and CSRF refresh requests.
// These counters describe actual RoundTrip calls, not guessed retry counts.
type attemptTransport struct {
	Requests, Responses, Errors, ReadErrors, PayloadSends, Redirects int
	Statuses                                                         [8]int
	DroppedStatuses                                                  int
}
type attemptTrace struct {
	mu        sync.Mutex
	transport attemptTransport
	phase     failureCode
}
type attemptTraceKey struct{}

func traceFrom(ctx context.Context) *attemptTrace {
	t, _ := ctx.Value(attemptTraceKey{}).(*attemptTrace)
	return t
}
func markAttemptPhase(ctx context.Context, phase failureCode) {
	if t := traceFrom(ctx); t != nil {
		t.mu.Lock()
		t.phase = phase
		t.mu.Unlock()
	}
}
func markPayloadSend(ctx context.Context) {
	if t := traceFrom(ctx); t != nil {
		t.mu.Lock()
		t.transport.PayloadSends++
		t.mu.Unlock()
	}
}
func markAttemptReadError(ctx context.Context) {
	if t := traceFrom(ctx); t != nil {
		t.mu.Lock()
		t.transport.ReadErrors++
		t.mu.Unlock()
	}
}
func (t *attemptTrace) roundTrip(req *http.Request, base http.RoundTripper) (*http.Response, error) {
	t.mu.Lock()
	t.transport.Requests++
	if req.Response != nil {
		t.transport.Redirects++
	}
	t.mu.Unlock()
	resp, err := base.RoundTrip(req)
	t.mu.Lock()
	if err != nil {
		t.transport.Errors++
	}
	if resp != nil {
		i := t.transport.Responses
		if i < len(t.transport.Statuses) {
			t.transport.Statuses[i] = resp.StatusCode
		} else {
			t.transport.DroppedStatuses++
		}
		t.transport.Responses++
	}
	t.mu.Unlock()
	return resp, err
}

// This private record is not a finding or a scheduler instruction. Literal
// matches are observations, not proof that this input caused executable output.
// PathID fingerprints the complete input, not a stable reflection/sink identity.
type attemptObservation struct {
	Run, ID, ParentID                                    uint64
	PathID, PayloadDigest, RequestDigest                 string
	Kind                                                 string
	Code                                                 verify.AssessmentCode
	Facts                                                verify.AssessmentFacts
	Transport                                            attemptTransport
	Failure                                              failureCode
	Status                                               int
	Duration                                             time.Duration
	Reflection                                           reflectionState
	Offset                                               int
	Payload, Snippet, Error, ParseError                  string
	SampleTruncated, AnalysisLimited, ResponseIncomplete bool
	IdentityIncomplete, RequestDigestPartial             bool
}
type observationSnapshot struct {
	Run                   uint64
	Total, DroppedSamples int
	ByCode                map[verify.AssessmentCode]int
	Samples               []attemptObservation
}
type observationLog struct {
	mu             sync.Mutex
	run, next      uint64
	total, dropped int
	byCode         map[verify.AssessmentCode]int
	paths          map[string]int
	samples        []attemptObservation
}

func (l *observationLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.run++
	l.next = 0
	l.total = 0
	l.dropped = 0
	l.byCode = nil
	l.paths = nil
	l.samples = nil
}
func (l *observationLog) begin(injection model.InjectionPoint, p payload.Payload, parent uint64, kind string) attemptObservation {
	l.mu.Lock()
	if l.run == 0 {
		l.run = 1
	}
	l.next++
	run, id := l.run, l.next
	l.mu.Unlock()
	h := sha256.New()
	// Cookies and proxy credentials are omitted by Target's JSON tags.
	// No credential material is logged; the digest is provenance only.
	err := json.NewEncoder(h).Encode(struct {
		Target    model.Target
		Cookies   []*http.Cookie
		ProxyAuth string
		Parameter model.Parameter
	}{injection.Target, injection.Target.Cookies, injection.Target.ProxyAuth, injection.Parameter})
	o := attemptObservation{Run: run, ID: id, ParentID: parent, Kind: kind, PathID: hex.EncodeToString(h.Sum(nil)), PayloadDigest: observationDigest(p.Value), Payload: p.Value, Reflection: reflectionUnknown, Offset: -1, Code: verify.AssessmentUnknown}
	if err != nil {
		o.IdentityIncomplete = true
		o.PathID = fmt.Sprintf("unknown-%d-%d", run, id)
	}
	return o
}
func observationDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func observationPrefix(value string, limit int) string {
	return strings.Clone(value[:min(len(value), limit)])
}
func (l *observationLog) record(o attemptObservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if o.Run != 0 && o.Run != l.run {
		return
	} // Never mix a late previous run.
	l.total++
	if l.byCode == nil {
		l.byCode = make(map[verify.AssessmentCode]int)
	}
	l.byCode[o.Code]++
	if l.paths == nil {
		l.paths = make(map[string]int)
	}
	count, exists := l.paths[o.PathID]
	if (!exists && len(l.paths) == maxObservationPaths) || count >= maxPathSamples || len(l.samples) == maxObservationSamples {
		l.dropped++
		return
	}
	l.paths[o.PathID] = count + 1
	o.SampleTruncated = o.SampleTruncated || len(o.Payload) > 512 || len(o.Snippet) > 512 || len(o.Error) > 256 || len(o.ParseError) > 256
	o.Payload = observationPrefix(o.Payload, 512)
	o.Snippet = observationPrefix(o.Snippet, 512)
	o.Error = observationPrefix(o.Error, 256)
	o.ParseError = observationPrefix(o.ParseError, 256)
	l.samples = append(l.samples, o)
}

// recorded returns the retained observation for one attempt id.
//
// It exists for the feedback loop: the derivation gate needs the facts of the
// attempt it just made, and the attempt id is the only reliable handle (a parent of
// 0 means "top level", so it cannot double as a sentinel). The second result is false
// when that attempt was dropped by the retention bounds — a dropped sample means the
// gate must treat the evidence as missing rather than infer anything from a
// neighbouring attempt.
func (l *observationLog) recorded(id uint64) (attemptObservation, bool) {
	if id == 0 {
		return attemptObservation{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.samples) - 1; i >= 0; i-- {
		if l.samples[i].ID == id {
			return l.samples[i], true
		}
	}
	return attemptObservation{}, false
}

func (l *observationLog) snapshot() observationSnapshot {
	l.mu.Lock()
	s := observationSnapshot{Run: l.run, Total: l.total, DroppedSamples: l.dropped, ByCode: make(map[verify.AssessmentCode]int), Samples: append([]attemptObservation(nil), l.samples...)}
	for code, count := range l.byCode {
		s.ByCode[code] = count
	}
	l.mu.Unlock()
	sort.Slice(s.Samples, func(i, j int) bool { return s.Samples[i].ID < s.Samples[j].ID })
	return s
}

var observationAngleEncoder = strings.NewReplacer("<", "&lt;", ">", "&gt;")

func observeResponse(o *attemptObservation, body []byte, value string) {
	if value == "" {
		return
	}
	if len(body) > maxObservationBody || len(value) > 4096 {
		o.AnalysisLimited = true
		return
	}
	text := string(body)
	index, length := strings.Index(text, value), len(value)
	if index >= 0 {
		o.Reflection = reflectionExact
	} else {
		// Full literal encodings only. No fuzzy fragment or whole-page character
		// counts justify an encoding/deletion or safety conclusion.
		for _, encoded := range []string{html.EscapeString(value), observationAngleEncoder.Replace(value)} {
			if encoded == value {
				continue
			}
			if at := strings.Index(text, encoded); at >= 0 {
				index, length = at, len(encoded)
				o.Reflection = reflectionHTMLEncoded
				break
			}
		}
	}
	if index < 0 {
		if !o.ResponseIncomplete {
			o.Reflection = reflectionNotObserved
		}
		return
	}
	o.Offset = index
	start := max(0, index-96)
	end := min(len(text), start+512)
	o.Snippet = observationPrefix(text[start:end], 512)
	o.SampleTruncated = start > 0 || end < len(text) || length > 512
}

func captureAttemptResponse(o *attemptObservation, resp *http.Response, body []byte, value string) {
	if resp == nil {
		return
	}
	o.Status = resp.StatusCode
	exchange := httpclient.CapturedSummary(resp)
	o.RequestDigest, o.RequestDigestPartial = exchange.RequestDigest, exchange.RequestTruncated
	o.ResponseIncomplete = exchange.ResponseIncomplete || len(body) >= httpclient.MaxResponseSize
	observeResponse(o, body, value)
}

type shadowAction string

const (
	shadowContinue shadowAction = "continue_coverage"
	shadowInspect  shadowAction = "inspect_unknown"
	shadowVerify   shadowAction = "verify_candidate"
	shadowRecover  shadowAction = "recover_or_report"
)

type shadowDecision struct {
	ID     uint64
	Action shadowAction
	Rule   string
}

// replayShadow never dispatches requests or suppresses work. Identical captured
// observations produce identical suggestions, irrespective of wall-clock time.
func replayShadow(samples []attemptObservation) []shadowDecision {
	decisions := make([]shadowDecision, 0, len(samples))
	for _, o := range samples {
		d := shadowDecision{ID: o.ID, Action: shadowContinue, Rule: "preserve_coverage"}
		switch {
		case o.Failure != failureNone || o.Status >= 400:
			d.Action, d.Rule = shadowRecover, "request_not_reliable"
		case o.AnalysisLimited || o.ResponseIncomplete || o.IdentityIncomplete || o.RequestDigestPartial || o.ParseError != "":
			d.Action, d.Rule = shadowInspect, "analysis_incomplete"
		case o.Code == verify.AssessmentCandidate && o.Facts.ContextConfirmed:
			d.Action, d.Rule = shadowVerify, "structural_candidate_only"
		case o.Reflection == reflectionHTMLEncoded || o.Code == verify.AssessmentContextUnconfirmed || o.Code == verify.AssessmentUnknown:
			d.Action, d.Rule = shadowInspect, "more_evidence_needed"
		}
		decisions = append(decisions, d)
	}
	return decisions
}

func finishAttempt(o *attemptObservation, trace *attemptTrace, started time.Time, err error) {
	trace.mu.Lock()
	o.Transport = trace.transport
	phase := trace.phase
	trace.mu.Unlock()
	o.Duration = time.Since(started)
	if err != nil {
		o.Error = err.Error()
		o.Failure = phase
		if o.Failure == failureNone {
			o.Failure = failureTransport
		}
		if errors.Is(err, context.Canceled) {
			o.Failure = failureCanceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			o.Failure = failureDeadline
		}
	}
}
