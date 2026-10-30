package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/xsscan/xsscan/pkg/model"
)

/*
Reflection path identity for incremental scheduling.

ENGINEERING_PLAN.md §25.3 requires that a scheduling decision be scoped to an
independent *path*, never to a parameter name or a whole site: "同名query/body必须不同;
不同租户/身份、原有参数值不能共享排除结论". §25.15 then records the gap this file
closes — the 25A PathID was a fingerprint of the whole input, which cannot
distinguish two reflection positions inside one response, so it could never be
used to stop work on one position without risking the others.

Two identity levels exist on purpose:

  - inputIdentity    identifies the *request*.
  - reflectionIdentity identifies a *reflection position* inside one response,
    built from context.Context.ReflectionKey().

Neither level is a finding, an exclusion, or a proof. They only tell the
scheduler which work is independent and which work is equivalent.
*/

// inputIdentity is the stable identity of one injection request.
//
// Deliberately NOT built from urlutil.NormalizeForDedup: that helper strips the
// query, which would collapse two different original query values into one
// identity. The plan names this explicitly ("调度不能复用会去掉query的
// NormalizeForDedup作为唯一身份"), so the raw escaped path and the untouched
// parameter values are part of the digest instead.
type inputIdentity struct {
	// Origin is scheme://host (including a non-default port).
	Origin string
	// Path is the escaped request path, so %2F and / stay distinct.
	Path string
	// Method is the effective HTTP method.
	Method string
	// ParamType and ParamName locate the injected parameter.
	ParamType model.ParamType
	ParamName string
	// BodyShape describes the request body's structure without its injected
	// values, so two bodies of different shape are different paths.
	BodyShape string
	// AuthDigest hashes identity-bearing request material: headers, cookies,
	// proxy credentials. Values are hashed, never stored, so the identity is
	// safe to keep in diagnostics.
	AuthDigest string
	// VariantDigest hashes the values of parameters that were NOT injected, so
	// two scans whose pre-existing values differ are different paths.
	VariantDigest string
	// Incomplete is set when any component could not be established. An
	// incomplete identity must never license a scheduling decision.
	Incomplete bool
}

// reflectionIdentity names one reflection position within one response.
type reflectionIdentity struct {
	// InputID scopes the position to its request.
	InputID string
	// Position is context.Context.ReflectionKey(): unit + type + offset +
	// tag/attr/quote. Empty when the context could not anchor itself.
	Position string
	// Index disambiguates several contexts that share a position key, which
	// happens when one response reflects the same value twice under the same
	// classification. It is an ordinal, not a stable identity.
	Index int
	// Anchored reports whether Position came from a real document location. It
	// is the explicit flag, not "Position != \"\"", so that a genuine key can
	// never be confused with the absence of one.
	Anchored bool
}

// pathID is the opaque, comparable handle the scheduler keys on.
type pathID string

// id renders the reflection identity into a single comparable path handle.
func (r reflectionIdentity) id() pathID {
	if !r.Anchored {
		// Still distinguishable from other unanchored positions, but marked as
		// not individually addressable.
		return pathID(r.InputID + "|unanchored|" + strconv.Itoa(r.Index))
	}
	return pathID(r.InputID + "|" + r.Position + "|" + strconv.Itoa(r.Index))
}

// buildInputIdentity derives the request-level identity from the target and the
// injection point, returning the canonical components alongside their digest.
func buildInputIdentity(target model.Target, injection model.InjectionPoint) (inputIdentity, string) {
	id := inputIdentity{
		ParamType: injection.Parameter.Type,
		ParamName: injection.Parameter.Name,
		Method:    target.HTTPMethod(),
	}

	u, err := url.Parse(target.URL)
	if err != nil || u.Host == "" {
		id.Incomplete = true
		return id, "identity-unavailable"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	id.Origin = scheme + "://" + strings.ToLower(u.Host)
	// EscapedPath keeps %2F distinct from /, so a path-parameter scan of
	// /a%2Fb is not confused with /a/b.
	id.Path = u.EscapedPath()
	if id.Path == "" {
		id.Path = "/"
	}

	id.BodyShape = bodyShape(target)
	id.AuthDigest = authDigest(target)
	id.VariantDigest = variantDigest(target, injection)

	digest, err := identityDigest(id)
	if err != nil {
		id.Incomplete = true
		return id, "identity-unavailable"
	}
	return id, digest
}

// identityDigest hashes the canonical JSON of an identity. The struct has no
// maps, so encoding is deterministic and the digest is reproducible.
func identityDigest(v any) (string, error) {
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(v); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// bodyShape describes the body's structure with injected values removed, so the
// identity tracks shape rather than the per-candidate payload.
func bodyShape(target model.Target) string {
	trimmed := strings.TrimSpace(target.Body)
	if trimmed == "" {
		return ""
	}
	ct := bodyMediaType(target)
	return ct + "|" + strings.Join(bodyKeys(trimmed, ct), ",")
}

// bodyMediaType returns the lowercased media type of the request body without
// its parameters. Boundary and charset vary per request and would otherwise make
// every request a new path.
func bodyMediaType(target model.Target) string {
	ct := ""
	for k, v := range target.Headers {
		if strings.EqualFold(k, "content-type") {
			ct = strings.ToLower(strings.TrimSpace(v))
			break
		}
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// mediaIsJSON reports whether the body should be read as a JSON object, by
// declared media type or, for servers that omit it, by a leading brace.
func mediaIsJSON(trimmed, ct string) bool {
	return strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{")
}

// bodyKeys extracts the structural key set of a request body: form or JSON
// field names, or a stable placeholder for opaque bodies.
func bodyKeys(trimmed, ct string) []string {
	if mediaIsJSON(trimmed, ct) {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			// Invalid or non-object JSON: keep the shape coarse but stable.
			return []string{"json-unparsed"}
		}
		keys := make([]string, 0, len(decoded))
		for k := range decoded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		values, err := url.ParseQuery(trimmed)
		if err != nil {
			return []string{"form-unparsed"}
		}
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	return []string{"opaque"}
}

// bodyFields returns the body's key/value pairs for identity purposes. It is
// media-type aware on purpose: parsing a JSON body with url.ParseQuery would
// treat the whole document as one key name, which leaks the injected value into
// the variant digest and gives every candidate its own path.
func bodyFields(trimmed, ct string) [][2]string {
	if mediaIsJSON(trimmed, ct) {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			return nil
		}
		pairs := make([][2]string, 0, len(decoded))
		for k, v := range decoded {
			pairs = append(pairs, [2]string{k, jsonValueString(v)})
		}
		return pairs
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		values, err := url.ParseQuery(trimmed)
		if err != nil {
			return nil
		}
		var pairs [][2]string
		for k, vs := range values {
			for _, v := range vs {
				pairs = append(pairs, [2]string{k, v})
			}
		}
		return pairs
	}
	return nil
}

// jsonValueString renders a decoded JSON value stably for hashing. Composite
// values fall back to their re-encoded form so nested structure still counts.
func jsonValueString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
		return ""
	}
}

// authDigest hashes headers, cookies and proxy credentials. Header and cookie
// values are part of the digest because an application may key behaviour on any
// of them (tenant, locale, identity), but they are never stored in the clear.
func authDigest(target model.Target) string {
	sum := sha256.New()

	names := make([]string, 0, len(target.Headers))
	for k := range target.Headers {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})
	for _, k := range names {
		sum.Write([]byte(strings.ToLower(k)))
		sum.Write([]byte{0})
		sum.Write([]byte(target.Headers[k]))
		sum.Write([]byte{1})
	}
	sum.Write([]byte{2})
	sum.Write([]byte(target.ProxyAuth))
	sum.Write([]byte{3})

	cookies := make([]string, 0, len(target.Cookies))
	for _, c := range target.Cookies {
		if c == nil {
			continue
		}
		// Name/domain/path identify the cookie; the value is folded in only as
		// a presence bit plus its hash so a session token is not recoverable.
		valueSum := sha256.Sum256([]byte(c.Value))
		cookies = append(cookies, c.Name+"\x00"+c.Domain+"\x00"+c.Path+"\x00"+hex.EncodeToString(valueSum[:]))
	}
	sort.Strings(cookies)
	for _, c := range cookies {
		sum.Write([]byte(c))
		sum.Write([]byte{4})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// variantDigest hashes the values of parameters that were NOT injected.
//
// The injected parameter is excluded on purpose: it is replaced by each
// candidate payload, so including it would give every candidate its own path and
// defeat the purpose of the identity. A different pre-existing value in any
// other parameter still yields a different path, because the server may branch
// on it.
func variantDigest(target model.Target, injection model.InjectionPoint) string {
	sum := sha256.New()
	writePairs := func(pairs [][2]string) {
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i][0] != pairs[j][0] {
				return pairs[i][0] < pairs[j][0]
			}
			return pairs[i][1] < pairs[j][1]
		})
		for _, p := range pairs {
			sum.Write([]byte(p[0]))
			sum.Write([]byte{0})
			sum.Write([]byte(p[1]))
			sum.Write([]byte{1})
		}
	}

	if u, err := url.Parse(target.URL); err == nil {
		var pairs [][2]string
		for k, vs := range u.Query() {
			if k == injection.Parameter.Name && injection.Parameter.Type == model.ParamQuery {
				continue
			}
			for _, v := range vs {
				pairs = append(pairs, [2]string{k, v})
			}
		}
		writePairs(pairs)
	}

	if trimmed := strings.TrimSpace(target.Body); trimmed != "" {
		var pairs [][2]string
		for _, pair := range bodyFields(trimmed, bodyMediaType(target)) {
			if pair[0] == injection.Parameter.Name && injection.Parameter.Type == model.ParamBody {
				continue
			}
			pairs = append(pairs, pair)
		}
		writePairs(pairs)
	}

	return hex.EncodeToString(sum.Sum(nil))
}

// reflectionIdentitiesFor lists the reflection positions an injection point can
// address, in detection order.
//
// All returned identities share one input identity, so two positions of the same
// parameter are independent paths even though they share a request. A context
// carrying no anchor yields Unanchored=true rather than being dropped: the plan
// forbids treating "cannot locate" as "covered elsewhere".
func reflectionIdentitiesFor(target model.Target, injection model.InjectionPoint) (inputIdentity, string, []reflectionIdentity) {
	input, inputID := buildInputIdentity(target, injection)

	out := make([]reflectionIdentity, 0, len(injection.Contexts))
	counts := make(map[string]int, len(injection.Contexts))
	for _, c := range injection.Contexts {
		key := c.ReflectionKey()
		index := counts[key]
		counts[key]++
		out = append(out, reflectionIdentity{
			InputID:  inputID,
			Position: key,
			Index:    index,
			Anchored: key != "",
		})
	}
	return input, inputID, out
}

// primaryPathID picks the path a candidate is attributed to when the payload
// cannot be tied to one position on its own: the first anchored position, else
// the first position, else a path scoped to the request alone.
func primaryPathID(inputID string, positions []reflectionIdentity) pathID {
	for _, p := range positions {
		if p.Anchored {
			return p.id()
		}
	}
	if len(positions) > 0 {
		return positions[0].id()
	}
	return pathID(inputID)
}
