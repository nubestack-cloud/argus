package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"argus/internal/redact"
)

// This file is the enforcement half of PROJECT.md T22's redaction
// constraint, and it is modelled directly on
// internal/agent/redact_egress_test.go — same argument, different egress.
// That file's guarantee is that a NEW TOOL cannot ship without redaction
// because ToolExecutor.Execute wraps the dispatch; this file's guarantee is
// that a NEW ATTRIBUTE cannot ship without redaction because the handler
// chain wraps the encoder.
//
// Both are structural rather than a matter of review discipline, for the
// same reason: the thing that actually failed in BUGS.md 84 was not a
// filter being wrong, it was there being no filter on a path somebody added
// later. A structured log attribute is exactly such a path.

// egressCanary is planted in every attribute shape a call site could use.
// One distinctive value, so any leak is unambiguous and greppable — the
// same convention as the agent's.
const egressCanary = "CANARY-9f21c4-must-never-egress"

// canaryBearer wraps the canary in a format internal/redact's pattern layer
// actually recognises. The pattern layer is bounded and format-driven (see
// its own doc comment): a bare random string is NOT a credential it claims
// to catch, so a test asserting a bare canary disappears would be asserting
// something this control never promised. Every case below therefore plants
// the canary inside a recognised shape.
var canaryBearer = "Authorization: Bearer " + egressCanary + "AAAAAAAA"

type stringerCanary struct{}

func (stringerCanary) String() string { return canaryBearer }

type structCanary struct {
	Note  string `json:"note"`
	Inner struct {
		Token string `json:"token"`
	} `json:"inner"`
}

// TestEveryAttributeShapeIsRedacted drives one canary through each shape an
// attribute value can take and asserts the raw credential never reaches the
// encoder. A new Kind handled in redactValue without a case here is caught
// by TestEveryValueKindIsClassifiedForRedaction below.
func TestEveryAttributeShapeIsRedacted(t *testing.T) {
	var sc structCanary
	sc.Note = canaryBearer
	sc.Inner.Token = canaryBearer

	cases := []struct {
		name string
		emit func(l *slog.Logger)
	}{
		{"message", func(l *slog.Logger) { l.Info(canaryBearer) }},
		{"string attr", func(l *slog.Logger) { l.Info("x", slog.String("k", canaryBearer)) }},
		{"Err helper", func(l *slog.Logger) { l.Info("x", Err(fmt.Errorf("%s", canaryBearer))) }},
		{"error via Any", func(l *slog.Logger) { l.Info("x", slog.Any("k", fmt.Errorf("%s", canaryBearer))) }},
		{"stringer via Any", func(l *slog.Logger) { l.Info("x", slog.Any("k", stringerCanary{})) }},
		{"bytes via Any", func(l *slog.Logger) { l.Info("x", slog.Any("k", []byte(canaryBearer))) }},
		{"string via Any", func(l *slog.Logger) { l.Info("x", slog.Any("k", canaryBearer)) }},
		{"struct via Any", func(l *slog.Logger) { l.Info("x", slog.Any("k", sc)) }},
		{"raw json via Any", func(l *slog.Logger) {
			l.Info("x", slog.Any("k", json.RawMessage(`{"note":"`+canaryBearer+`"}`)))
		}},
		{"group", func(l *slog.Logger) {
			l.Info("x", slog.Group("g", slog.String("k", canaryBearer)))
		}},
		{"WithAttrs on a derived logger", func(l *slog.Logger) {
			l.With(slog.String("k", canaryBearer)).Info("x")
		}},
		{"WithGroup on a derived logger", func(l *slog.Logger) {
			l.WithGroup("g").Info("x", slog.String("k", canaryBearer))
		}},
		{"context-injected attr", func(l *slog.Logger) {
			ctx := ContextWith(context.Background(), slog.String("k", canaryBearer))
			l.InfoContext(ctx, "x")
		}},
		{"bridged standard log line", func(l *slog.Logger) { log.Printf("legacy: %s", canaryBearer) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := SetupForTesting(&buf, slog.LevelDebug)
			defer restore()
			prevOut, prevFlags := log.Writer(), log.Flags()
			bridgeStandardLog()
			defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()

			tc.emit(For("test"))

			out := buf.String()
			if out == "" {
				t.Fatalf("nothing was written")
			}
			if strings.Contains(out, egressCanary) {
				t.Fatalf("credential reached the encoder unredacted:\n%s", out)
			}
			if !strings.Contains(out, redact.Marker) {
				t.Fatalf("expected %s in the output, got:\n%s", redact.Marker, out)
			}
		})
	}
}

// valueKindCoverage is the authoritative classification of every slog value
// Kind, mirroring the agent's toolRedactionCoverage map. "filtered" means
// redactValue rewrites it; "inert" means it is passed through deliberately
// because no recognised credential format can be carried in it.
//
// TestEveryValueKindIsClassifiedForRedaction fails if the standard library
// grows a Kind this map does not name, so "add a Kind, decide about
// redaction" is true by construction rather than by memory.
var valueKindCoverage = map[slog.Kind]string{
	slog.KindString:    "filtered",
	slog.KindAny:       "filtered",
	slog.KindGroup:     "filtered",
	slog.KindLogValuer: "filtered",

	slog.KindBool:     "inert",
	slog.KindDuration: "inert",
	slog.KindFloat64:  "inert",
	slog.KindInt64:    "inert",
	slog.KindTime:     "inert",
	slog.KindUint64:   "inert",
}

func TestEveryValueKindIsClassifiedForRedaction(t *testing.T) {
	// slog.Kind's String() returns an "<unknown ...>" placeholder past the
	// last defined Kind, which is how a newly added Kind announces itself.
	for k := slog.Kind(0); !strings.HasPrefix(k.String(), "<unknown"); k++ {
		if _, ok := valueKindCoverage[k]; !ok {
			t.Fatalf("slog.Kind %q is not classified in valueKindCoverage — decide whether it is filtered or inert and say why", k)
		}
	}
}

// TestRedactionIsInsideTheContextHandler pins the chain ORDER. Context
// attributes are injected by the outer handler and must still pass through
// the redacting one; an inverted chain would redact only what the call site
// named and let anything the context carried through untouched.
func TestRedactionIsInsideTheContextHandler(t *testing.T) {
	h := newChain(&bytes.Buffer{}, slog.LevelInfo, formatJSON)
	ch, ok := h.(*contextHandler)
	if !ok {
		t.Fatalf("outermost handler is %T, want *contextHandler", h)
	}
	if _, ok := ch.next.(*redactHandler); !ok {
		t.Fatalf("handler under the context handler is %T, want *redactHandler", ch.next)
	}
}

// TestNoPackageBuildsItsOwnHandler is the bypass check: internal/logging is
// the only place in the tree that may construct a slog handler, install a
// default, or redirect the standard log package. Anywhere else, those calls
// would produce a logger that writes straight to an encoder with no
// redaction pass and no context attributes — the exact bypass this package
// exists to make unreachable.
func TestNoPackageBuildsItsOwnHandler(t *testing.T) {
	banned := map[string]string{
		"slog.NewJSONHandler": "builds an encoder with no redaction pass — use logging.For(component)",
		"slog.NewTextHandler": "builds an encoder with no redaction pass — use logging.For(component)",
		"slog.SetDefault":     "replaces the installed chain — only logging.Setup may do this",
		"slog.New":            "wraps a handler directly — use logging.For(component)",
		"log.SetOutput":       "redirects the bridged standard logger — only logging.bridgeStandardLog may do this",
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "web", "node_modules", ".git", "logging":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := pkg.Name + "." + sel.Sel.Name
			if why, banned := banned[name]; banned {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d: %s outside internal/logging: %s",
					rel, fset.Position(call.Pos()).Line, name, why)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
