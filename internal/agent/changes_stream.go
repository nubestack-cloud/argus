package agent

import (
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"argus/internal/agent/changes"
	"argus/internal/agent/objcache"
	"argus/internal/redact"
	"argus/internal/tunnel"
)

// The change stream (docs/CLUSTER_INSIGHT_SPECS.md CI-S2): the object
// cache's add/update/delete events, diffed per kind by internal/agent/changes,
// buffered here and flushed to the hub as ChangeBatch messages by the tunnel
// session. The buffer lives for the process, so changes made while the
// tunnel is down are delivered on reconnect; anything that cannot be kept
// (overflow, a failed send) becomes a gap record so the hub can say the
// history is incomplete there rather than imply nothing changed.

const (
	changeBufferMax       = 10000
	changeBatchMax        = 500
	changeBatchMaxBytes   = 256 << 10
	changeFlushInterval   = 5 * time.Second
	changeBatchesPerFlush = 8
)

type changeStream struct {
	mu        sync.Mutex
	buf       []tunnel.ResourceChange
	gaps      []tunnel.ChangeGap
	overflow  *tunnel.ChangeGap
	maxBuffer int
	now       func() time.Time
}

var activeChangeStream = &changeStream{maxBuffer: changeBufferMax, now: time.Now}

// hubAcceptsChanges is set when the current tunnel session's hub advertises
// tunnel.HubFeatureChangeBatch on an ack; reset at each session start.
var hubAcceptsChanges atomic.Bool

// subscribe feeds the stream from a cache. Runs on informer goroutines, so
// it only diffs and appends.
func (s *changeStream) subscribe(c *objcache.Cache) {
	c.OnChange(func(ch objcache.Change) {
		ev, ok := changes.BuildEvent(ch.Kind, ch.Group, ch.Op, ch.Old, ch.New, ch.At)
		if !ok {
			return
		}
		s.push(toWireChange(ev))
	})
}

func toWireChange(ev changes.ChangeEvent) tunnel.ResourceChange {
	rc := tunnel.ResourceChange{
		ObservedAt: ev.ObservedAt, Kind: ev.Kind, APIGroup: ev.APIGroup, Namespace: ev.Namespace, Name: ev.Name,
		UID: ev.UID, OwnerKind: ev.OwnerKind, OwnerName: ev.OwnerName, Op: ev.Op, Summary: ev.Summary,
	}
	for _, f := range ev.Fields {
		rc.Fields = append(rc.Fields, tunnel.ChangeField{Path: f.Path, OldValue: f.OldValue, NewValue: f.NewValue})
	}
	return rc
}

func (s *changeStream) push(rc tunnel.ResourceChange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) >= s.maxBuffer {
		if s.overflow == nil {
			s.overflow = &tunnel.ChangeGap{From: rc.ObservedAt, Reason: "agent change buffer full (hub unreachable or changes arriving faster than they could be sent)"}
		}
		s.overflow.To = rc.ObservedAt
		return
	}
	if s.overflow != nil {
		s.gaps = append(s.gaps, *s.overflow)
		s.overflow = nil
	}
	s.buf = append(s.buf, rc)
}

// recordGap notes a window whose changes were lost after leaving the buffer.
func (s *changeStream) recordGap(from, to time.Time, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gaps = append(s.gaps, tunnel.ChangeGap{From: from, To: to, Reason: reason})
}

// drain takes up to one batch off the buffer, redacted and ready to send.
// Nil when there is nothing to send.
func (s *changeStream) drain() *tunnel.ChangeBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) == 0 && len(s.gaps) == 0 {
		return nil
	}
	b := &tunnel.ChangeBatch{Gaps: s.gaps}
	s.gaps = nil
	size := 0
	n := 0
	for n < len(s.buf) && n < changeBatchMax {
		redactChange(&s.buf[n])
		size += approxChangeSize(s.buf[n])
		if size > changeBatchMaxBytes && n > 0 {
			break
		}
		n++
	}
	b.Changes = append([]tunnel.ResourceChange(nil), s.buf[:n]...)
	s.buf = append(s.buf[:0], s.buf[n:]...)
	return b
}

func approxChangeSize(rc tunnel.ResourceChange) int {
	n := len(rc.Kind) + len(rc.Namespace) + len(rc.Name) + len(rc.Summary) + 128
	for _, f := range rc.Fields {
		n += len(f.Path) + 600 // values are capped at 256 runes each
	}
	return n
}

// sensitiveChangePath matches change paths whose values must never leave
// the agent. The differ already emits only "added/removed/modified" for
// these; this is the egress backstop if a differ ever changes.
var sensitiveChangePath = regexp.MustCompile(`(\.env\.)|(^(data|stringData|binaryData)\.)|(last-applied-configuration)`)

// redactChange is the change stream's capture-time redaction chokepoint —
// the equivalent of ToolExecutor.Execute and the finding Message filter for
// this egress path (argus-context non-negotiable 9). Every change passes
// here, once, before it is placed in a batch.
func redactChange(rc *tunnel.ResourceChange) {
	rc.Summary = redact.Text(rc.Summary)
	for i := range rc.Fields {
		f := &rc.Fields[i]
		if sensitiveChangePath.MatchString(f.Path) {
			f.OldValue = markerIfSet(f.OldValue)
			f.NewValue = markerIfSet(f.NewValue)
			continue
		}
		f.OldValue = redactValue(f.OldValue, 0)
		f.NewValue = redactValue(f.NewValue, 0)
	}
}

func markerIfSet(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		switch t {
		case changes.ValueAdded, changes.ValueRemoved, changes.ValueModified:
			return t
		}
	}
	return redact.Marker
}

func redactValue(v any, depth int) any {
	if depth > 16 {
		return redact.Marker
	}
	switch t := v.(type) {
	case string:
		return redact.Text(t)
	case []any:
		for i := range t {
			t[i] = redactValue(t[i], depth+1)
		}
		return t
	case []string:
		out := make([]any, len(t))
		for i := range t {
			out[i] = redact.Text(t[i])
		}
		return out
	case map[string]any:
		for k, x := range t {
			t[k] = redactValue(x, depth+1)
		}
		return t
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = redact.Text(x)
		}
		return out
	default:
		return v
	}
}
