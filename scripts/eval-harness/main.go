// Command eval-harness runs the golden eval corpus and reports two scores:
// the root-cause match rate and the honest-negative rate. It is the
// regression gate on this product's central claim — that it reaches the
// right root cause — which until now had no gate of any kind: a prompt edit,
// a tool-schema change or a model upgrade could degrade diagnostic accuracy
// fleet-wide and every test in this repo would stay green (PROJECT.md E19).
//
// It lives under scripts/ rather than cmd/ because it is test support, not a
// product binary — the same convention scripts/fake-llm-server and
// scripts/simulate-finding follow.
//
// # Two modes
//
//	-mode offline  (default)  No hub, no Postgres, no tunnel, no cluster.
//	                          Uses the REAL internal/llm.SystemPrompt and the
//	                          REAL internal/llm.InvestigationToolSchemas, and
//	                          drives the turn loop itself (see offline.go for
//	                          exactly what that does and does not make real).
//	                          This is what the nightly runs, because a gate
//	                          that needs a built image and a running stack
//	                          before it can produce a number is a gate that
//	                          does not get run.
//
//	-mode stack               The full production path: real login, real
//	                          enrollment, a real mTLS tunnel from a fake agent
//	                          answering the case's fixture, and a real
//	                          POST /incidents/{id}/analyze driving the real
//	                          internal/llm loop. Needs a running
//	                          `docker compose -f deploy/compose/docker-compose.yaml up`
//	                          stack. More faithful, much more expensive.
//
// # The subject
//
// With -llm-base-url set, the subject is a real model and the run measures
// diagnostic accuracy. Without it, the subject is reasoner.go's deterministic
// stand-in, which obeys exactly the instructions the real system prompt
// contains — so the run measures whether the PROMPT still carries what a
// correct investigation needs, and says so, loudly, in its own output. The
// two claims are not interchangeable and the report never lets them blur.
//
// # Usage
//
//	go run ./scripts/eval-harness                                   # the nightly's run
//	go run ./scripts/eval-harness -personality bad                  # the scoring's own sanity check
//	go run ./scripts/eval-harness -repeat 10                        # run-to-run variance
//	go run ./scripts/eval-harness -llm-base-url ... -llm-model ...  # measure a real model
//	go run ./scripts/eval-harness -mode stack                       # the full real-hub path
//	go run ./scripts/eval-harness -mode stack -stack-use-configured-provider -repeat 3
//	                                                                # measure the model the hub is
//	                                                                # ALREADY configured with, three
//	                                                                # times, for the run-to-run spread
//
// # Measuring a real model when the hub's provider is a `cli` runner
//
// -llm-base-url reaches an OpenAI-compatible endpoint only. A hub whose
// active ai_providers row is kind=cli (a coding-agent CLI behind a runner
// service, ADR-17) has no such endpoint, so that flag cannot address it at
// all. -mode stack -stack-use-configured-provider is the route to a real
// number in that shape: the harness touches no provider settings, and the
// analyze call it makes goes wherever the hub is already pointed. What the
// hub is pointed at is then READ BACK from GET /admin/settings and printed
// as the subject, so the report names the thing that actually answered
// rather than the thing the harness meant to configure.
//
// # Logging: deliberately NOT converted to internal/logging (PROJECT.md T22)
//
// T22 converts the hub's and agent's log.Printf call sites to structured slog
// records. The programs under scripts/ are excluded from that, permanently and
// on purpose — this is a decision, not a gap:
//
//   - They are dev/CI tooling, `go run` and `go build` throwaways. Nothing
//     under deploy/ or the Dockerfile builds them into a shipped image, so
//     none of their output ever reaches a support bundle or a log shipper,
//     which is the operability defect T22 exists to fix.
//   - None of them calls logging.Setup(), so their output is plain text read
//     by the person who just ran them. Converting would make it JSON, which
//     is strictly worse at a terminal, and the structured fields it would buy
//     (request_id, incident_id, cluster_id, actor_id) do not exist here:
//     there is no request, no actor, and no hub-side correlation to join to.
//   - CI reads some of this output as text (.github/workflows/eval.yml tees
//     and greps the eval harness's), so the format is an interface.
//
// The standard `log` package is the right tool for a terminal program. Use it
// here; use internal/logging under cmd/ and internal/.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"argus/scripts/eval/casefmt"
)

// Score floors the harness exits non-zero below. They are a RECORDED
// BASELINE of what the configured subject currently achieves, not an
// aspiration: a floor above what the subject actually scores makes the
// nightly permanently red, and a permanently red nightly is read exactly as
// often as no nightly at all (see .github/workflows/nightly-failure-issue.yml
// for the two times that already happened in this repo).
//
// Both default to 1.0 because the deterministic stand-in, against the real
// prompt, scores 100% on both corpora — it is deterministic, so anything
// below 100% means something changed. A real-model run has to pass its own
// measured floors on the command line instead; there is no honest default
// for a number nobody has measured yet.
const (
	DefaultMinRootCauseRate      = 1.0
	DefaultMinHonestNegativeRate = 1.0
)

func main() {
	// --- shared ---
	mode := flag.String("mode", "offline", `"offline" (no hub, no Postgres, no cluster — what the nightly runs) or "stack" (the full real-hub path; needs a running docker compose stack)`)
	goldenDirs := flag.String("golden-dirs", "scripts/eval/golden,scripts/eval/generated", "comma-separated corpus directories")
	personality := flag.String("personality", "good", `deterministic stand-in to run when no model backend is configured: "good" or "bad" (see reasoner.go); ignored if -llm-base-url is set`)
	llmBaseURLFlag := flag.String("llm-base-url", "", "point at a REAL OpenAI-compatible provider instead of the deterministic stand-in — this is the only configuration under which the run measures a model's diagnostic accuracy at all")
	llmModelFlag := flag.String("llm-model", "", "model name to pair with -llm-base-url")
	llmAPIKeyFlag := flag.String("llm-api-key", "", "API key to pair with -llm-base-url, if the provider needs one (never logged)")
	repeat := flag.Int("repeat", 1, "run the whole corpus this many times and report the run-to-run spread of both scores — this is the measurement that decides whether the gate can ever become a required check. Works in both modes; against a real model it is the only way to learn whether the score moves on its own")
	caseIDs := flag.String("case-ids", "", "comma-separated case IDs to run instead of the whole corpus — for a real-model run that is too expensive to repeat in full. The report names exactly which cases ran, so a subset can never be mistaken for the corpus")
	reportJSON := flag.String("report-json", "", "also write the run's scores to this path as JSON, for tracking the numbers over time")
	minRootCause := flag.Float64("min-root-cause-rate", DefaultMinRootCauseRate, "exit non-zero if the root-cause match rate falls below this")
	minHonestNegative := flag.Float64("min-honest-negative-rate", DefaultMinHonestNegativeRate, "exit non-zero if the honest-negative rate falls below this")

	// --- stack mode only ---
	apiBase := flag.String("api", "http://localhost:8080", "stack mode: hub API base URL")
	tunnelAddr := flag.String("tunnel-addr", "localhost:8443", "stack mode: hub mTLS tunnel address (host:port)")
	tunnelServerName := flag.String("tunnel-server-name", "localhost", "stack mode: TLS ServerName to present when dialing the tunnel")
	composeFile := flag.String("compose-file", "deploy/compose/docker-compose.yaml", "stack mode: path to the running stack's docker-compose.yaml")
	adminEmail := flag.String("admin-email", "admin@localhost", "stack mode: hub admin email")
	adminPassword := flag.String("admin-password", os.Getenv("ARGUS_ADMIN_PASSWORD"), "stack mode: hub admin password (falls back to scraping the hub-api container log)")
	llmHost := flag.String("llm-host", "host.docker.internal", `stack mode: hostname the hub container can reach this harness at`)
	useConfiguredProvider := flag.Bool("stack-use-configured-provider", false, "stack mode: leave the hub's AI provider settings ALONE and measure whatever it is already configured with. This is the only way to reach a kind=cli provider (a coding-agent CLI behind a runner service), which -llm-base-url cannot address, and it is the only stack-mode setting under which the harness writes nothing to a running stack's configuration")
	analyzeTimeout := flag.Duration("stack-analyze-timeout", 15*time.Minute, "stack mode: how long to wait for one POST /incidents/{id}/analyze's investigation to land (the request itself answers 202 at once). Generous on purpose — the hub bounds the investigation itself, and a client that gives up early reports a failure that did not happen on an analysis it has already paid for")
	cleanup := flag.Bool("stack-cleanup", true, "stack mode: delete the throwaway incidents, findings, analyses and enrolled cluster this run created. Audit rows are deliberately NOT deleted — audit_events is a verified hash chain (argusctl audit verify), and punching a hole in it to tidy up an eval run would break the thing it exists to prove")

	flag.Parse()

	if *personality != "good" && *personality != "bad" {
		log.Fatalf("eval-harness: -personality must be \"good\" or \"bad\", got %q", *personality)
	}

	var dirs []string
	for _, d := range strings.Split(*goldenDirs, ",") {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, d)
		}
	}
	cases, err := LoadGoldenCaseDirs(dirs)
	if err != nil {
		log.Fatalf("eval-harness: %v", err)
	}
	log.Printf("eval-harness: loaded %d case(s) from %s", len(cases), strings.Join(dirs, ", "))

	corpusSize := len(cases)
	if *caseIDs != "" {
		cases, err = SelectCases(cases, *caseIDs)
		if err != nil {
			log.Fatalf("eval-harness: %v", err)
		}
		log.Printf("eval-harness: -case-ids selected %d of %d case(s): %s", len(cases), corpusSize, *caseIDs)
	}

	opt := OfflineOptions{
		LLMBaseURL:  *llmBaseURLFlag,
		LLMModel:    *llmModelFlag,
		LLMAPIKey:   *llmAPIKeyFlag,
		Personality: *personality,
	}

	var runs []Scores
	var last []CaseResult
	// allResults keeps EVERY pass's per-case outcomes, not just the last.
	// Over a deterministic subject the passes are identical and the extra
	// slice is waste; over a real model they are the whole point — "the mean
	// moved by 4 points" and "these two cases flipped and the rest held" are
	// different findings, and only the second one says whether a gate could
	// ever be stable.
	var allResults [][]CaseResult

	// subject/measuresRealModel describe what actually produced the answers.
	// In offline mode the harness IS the whole configuration, so its own
	// options can say. In stack mode they cannot: the hub decides which
	// provider it uses, and it does not have to agree with what the harness
	// asked for — so runAgainstStack reads the answer back off the hub and
	// returns it here (see stackSubject).
	subject := opt.Subject()
	measuresRealModel := opt.MeasuresRealModel()
	var stackCaveats string

	if *repeat < 1 {
		log.Fatalf("eval-harness: -repeat must be at least 1, got %d", *repeat)
	}

	switch *mode {
	case "offline":
		for i := 1; i <= *repeat; i++ {
			results, err := RunCorpusOffline(cases, opt)
			if err != nil {
				log.Fatalf("eval-harness: %v", err)
			}
			last = results
			allResults = append(allResults, results)
			runs = append(runs, Aggregate(results))
			if *repeat > 1 {
				logRunScores(i, *repeat, runs[len(runs)-1])
			}
		}

	case "stack":
		allRuns, subj, err := runAgainstStack(cases, stackOptions{
			APIBase:               *apiBase,
			TunnelAddr:            *tunnelAddr,
			TunnelServerName:      *tunnelServerName,
			ComposeFile:           *composeFile,
			AdminEmail:            *adminEmail,
			AdminPassword:         *adminPassword,
			LLMHost:               *llmHost,
			Personality:           *personality,
			LLMBaseURL:            *llmBaseURLFlag,
			LLMModel:              *llmModelFlag,
			LLMAPIKey:             *llmAPIKeyFlag,
			UseConfiguredProvider: *useConfiguredProvider,
			AnalyzeTimeout:        *analyzeTimeout,
			Cleanup:               *cleanup,
			Repeat:                *repeat,
		})
		if err != nil {
			log.Fatalf("eval-harness: %v", err)
		}
		for _, results := range allRuns {
			last = results
			allResults = append(allResults, results)
			runs = append(runs, Aggregate(results))
		}
		subject = subj.Description
		measuresRealModel = subj.MeasuresRealModel
		stackCaveats = subj.Caveats

	default:
		log.Fatalf("eval-harness: -mode must be \"offline\" or \"stack\", got %q", *mode)
	}

	// The per-case table is the LAST pass's, and says so when there was more
	// than one. Printing three tables would bury the scores; printing one
	// without labelling it invites reading a single pass's verdicts as the
	// run's. The per-case stability list below is where every pass is
	// compared.
	if len(runs) > 1 {
		fmt.Printf("\n(The per-case table below is the LAST of %d runs. Per-case outcomes across\nall %d are compared in the stability list at the end, and recorded in full by\n-report-json.)\n", len(runs), len(runs))
	}
	fmt.Println(Report(last, subject))
	if stackCaveats != "" {
		fmt.Print(stackCaveats)
	}
	if len(cases) < corpusSize {
		fmt.Print(SubsetBanner(cases, corpusSize, *caseIDs))
	}

	if len(runs) > 1 {
		fmt.Print(VarianceReport(runs, measuresRealModel))
		fmt.Print(CaseStabilityReport(allResults))
	}
	if !measuresRealModel {
		fmt.Print(NotMeasuredBanner(*mode))
	}

	final := Aggregate(last)
	if *reportJSON != "" {
		if err := writeScoreJSON(*reportJSON, subject, measuresRealModel, runs, allResults); err != nil {
			log.Fatalf("eval-harness: write report JSON: %v", err)
		}
	}

	failed := false
	if final.RootCauseTotal > 0 && final.RootCauseRate() < *minRootCause {
		fmt.Printf("\nFAIL: root-cause match rate %.3f is below the floor of %.3f\n", final.RootCauseRate(), *minRootCause)
		failed = true
	}
	if final.HonestNegativeN > 0 && final.HonestNegativeRate() < *minHonestNegative {
		fmt.Printf("FAIL: honest-negative rate %.3f is below the floor of %.3f\n", final.HonestNegativeRate(), *minHonestNegative)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
}

// NotMeasuredBanner is printed whenever a run had no model backend. It says,
// in the output a person actually reads, that nothing about a model's
// diagnostic accuracy was measured — so a green run cannot be quoted as
// evidence that it was.
func NotMeasuredBanner(mode string) string {
	return "\n--- DIAGNOSTIC ACCURACY WAS NOT MEASURED BY THIS RUN ---\n" +
		"No model backend was configured (-llm-base-url is empty), so the subject was the\n" +
		"deterministic stand-in. What this run DID check is that the system prompt still\n" +
		"carries the instructions a correct investigation depends on, and that the tool\n" +
		"schemas, corpus and scoring are intact — a prompt edit or a tool-schema change\n" +
		"moves these numbers. What it did NOT check is whether any model still reasons\n" +
		"correctly. Pass -llm-base-url/-llm-model to measure that, and record the floors\n" +
		"it achieves before treating them as a gate.\n"
}

// VarianceReport is the number that decides whether this can ever become a
// required check. A score that moves on its own makes a gate flaky, a flaky
// required check gets bypassed, and a bypassed check is worse than none — so
// the spread is measured before anything is gated on the mean.
func VarianceReport(runs []Scores, measuresRealModel bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n--- run-to-run variance over %d runs ---\n", len(runs))
	rc := make([]float64, 0, len(runs))
	hn := make([]float64, 0, len(runs))
	for _, s := range runs {
		rc = append(rc, s.RootCauseRate())
		hn = append(hn, s.HonestNegativeRate())
	}
	fmt.Fprintf(&b, "root-cause match rate: %s\n", spreadOf(rc))
	fmt.Fprintf(&b, "honest-negative rate:  %s\n", spreadOf(hn))
	if measuresRealModel {
		b.WriteString("This spread IS the number a gating decision needs: it came from a real model,\n")
		b.WriteString("re-answering the same corpus. Read it with the per-case stability list below —\n")
		b.WriteString("a spread produced by one borderline case and a spread produced by the whole\n")
		b.WriteString("corpus drifting have opposite implications for a floor. Note also that these\n")
		b.WriteString("runs are consecutive against one provider on one day: they bound short-term\n")
		b.WriteString("sampling noise, not the larger jump a model or prompt version change makes.\n")
	} else {
		b.WriteString("A zero spread from a deterministic subject is a property of the SUBJECT, not\n")
		b.WriteString("evidence that a real model's score is stable. Only a repeat run against a real\n")
		b.WriteString("model produces the number a gating decision needs.\n")
	}
	return b.String()
}

func spreadOf(xs []float64) string {
	if len(xs) == 0 {
		return "no runs"
	}
	min, max, sum := xs[0], xs[0], 0.0
	for _, x := range xs {
		if x < min {
			min = x
		}
		if x > max {
			max = x
		}
		sum += x
	}
	mean := sum / float64(len(xs))
	varSum := 0.0
	for _, x := range xs {
		varSum += (x - mean) * (x - mean)
	}
	sd := math.Sqrt(varSum / float64(len(xs)))
	return fmt.Sprintf("mean %.3f, min %.3f, max %.3f, spread %.3f, sd %.3f", mean, min, max, max-min, sd)
}

// scoreReport is the machine-readable form, for tracking the numbers over
// time. Deliberately carries `measuresRealModel` and `subject`: a row of
// scores with no record of what produced them is how a prompt-contract number
// gets quoted later as an accuracy number.
type scoreReport struct {
	Subject           string        `json:"subject"`
	MeasuresRealModel bool          `json:"measuresRealModel"`
	Runs              []scoreRunRow `json:"runs"`
	Cases             []scoreCase   `json:"cases"`
}

type scoreRunRow struct {
	RootCauseMatched   int     `json:"rootCauseMatched"`
	RootCauseTotal     int     `json:"rootCauseTotal"`
	RootCauseRate      float64 `json:"rootCauseRate"`
	HonestNegativeHit  int     `json:"honestNegativeHit"`
	HonestNegativeN    int     `json:"honestNegativeTotal"`
	HonestNegativeRate float64 `json:"honestNegativeRate"`
	// Cases is this pass's own per-case outcomes. Recorded per pass rather
	// than once for the run because a repeat against a real model exists to
	// find out WHICH cases move, and a single final-pass listing cannot say.
	Cases []scoreCase `json:"cases"`
}

type scoreCase struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Provenance string `json:"provenance"`
	Pass       bool   `json:"pass"`
	Detail     string `json:"detail"`
	// Statement is what the subject actually concluded, kept verbatim. Two
	// passes can both fail a case for entirely different reasons, and the
	// detail line alone flattens that.
	Statement  string   `json:"statement,omitempty"`
	Status     string   `json:"status,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Iterations int      `json:"iterations,omitempty"`
}

func scoreCaseOf(r CaseResult) scoreCase {
	kind := "root-cause"
	if r.Case.Expected.Type == casefmt.ExpectInsufficient {
		kind = "honest-negative"
	}
	return scoreCase{
		ID: r.Case.ID, Kind: kind, Provenance: r.Case.Provenance,
		Pass: r.CorrectnessPass, Detail: r.CorrectnessDetail,
		Statement: r.Response.RootCause, Status: r.Response.Status,
		Confidence: r.Response.Confidence, Iterations: r.Response.Iterations,
	}
}

// writeScoreJSON records every pass, and the last pass's cases at the top
// level as well — the top-level Cases list is what already-written readers
// of this file expect, and dropping it would break them to save a few lines.
func writeScoreJSON(path, subject string, measuresRealModel bool, runs []Scores, allResults [][]CaseResult) error {
	rep := scoreReport{Subject: subject, MeasuresRealModel: measuresRealModel}
	for i, s := range runs {
		row := scoreRunRow{
			RootCauseMatched: s.RootCauseMatched, RootCauseTotal: s.RootCauseTotal, RootCauseRate: s.RootCauseRate(),
			HonestNegativeHit: s.HonestNegativeHit, HonestNegativeN: s.HonestNegativeN, HonestNegativeRate: s.HonestNegativeRate(),
		}
		if i < len(allResults) {
			for _, r := range allResults[i] {
				row.Cases = append(row.Cases, scoreCaseOf(r))
			}
		}
		rep.Runs = append(rep.Runs, row)
	}
	if len(allResults) > 0 {
		for _, r := range allResults[len(allResults)-1] {
			rep.Cases = append(rep.Cases, scoreCaseOf(r))
		}
	}
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// stackOptions is the full-stack run's configuration.
type stackOptions struct {
	APIBase, TunnelAddr, TunnelServerName string
	ComposeFile                           string
	AdminEmail, AdminPassword             string
	LLMHost, Personality                  string
	LLMBaseURL, LLMModel, LLMAPIKey       string

	// UseConfiguredProvider leaves the hub's AI provider settings untouched
	// and measures whatever it already points at. See the flag's own help
	// text: it is the only way to reach a kind=cli provider, and the only
	// stack-mode setting that writes nothing to a running stack's config.
	UseConfiguredProvider bool

	// Cleanup deletes the throwaway rows and the throwaway cluster this run
	// created. Audit rows are never deleted — see cleanupStackRun.
	Cleanup bool

	// Repeat runs the whole (possibly subsetted) corpus this many times over
	// ONE enrollment and ONE tunnel connection, producing one Scores per pass
	// for the variance report.
	Repeat int

	// AnalyzeTimeout bounds the harness's own wait for one analysis to land.
	// See apiClient.analyzeWait.
	AnalyzeTimeout time.Duration
}

// stackSubject is what a stack run actually measured, as read back off the
// hub rather than as the harness intended it.
//
// The distinction is the point. PUT /admin/settings edits the ACTIVE ai
// provider in place and preserves its kind (internal/settings.
// UpdateActiveProvider), and internal/settings' ProviderInput.clearedForKind
// blanks base_url/model on a kind=cli row — so pointing -llm-base-url at a
// hub whose active provider is a CLI runner writes a value the hub then
// ignores, and the analyze call goes to the real model behind that runner
// anyway. Deriving the subject line from the harness's own flags would print
// "DETERMINISTIC STAND-IN" over numbers a real, billed model produced. It is
// read back instead, and a disagreement is a hard error.
type stackSubject struct {
	Description       string
	MeasuresRealModel bool

	// Caveats is printed under the report, for things true of THIS subject
	// that would otherwise be read as a result. The cli backend's iteration
	// count is the standing example — see describeConfiguredProvider.
	Caveats string
}

// runAgainstStack is the original harness path, unchanged in what it does:
// real login, real enrollment, real accept, real mTLS tunnel from a fake
// agent, and a real POST /incidents/{id}/analyze per case. The only two
// stand-ins are the cluster a tool call would hit (fakeagent.go, answering
// from the case's fixture) and — unless a real provider is configured — the
// model (reasoner.go).
//
// It returns one []CaseResult per repeat. Enrollment, the tunnel and the
// provider configuration are done once and shared across every pass: a
// repeat exists to measure the SUBJECT's run-to-run spread, so re-enrolling
// a fresh cluster each time would add a second source of variation to the
// one number the run is trying to isolate.
func runAgainstStack(cases []GoldenCase, o stackOptions) ([][]CaseResult, stackSubject, error) {
	var subject stackSubject

	resolvedPassword, err := resolveAdminPassword(o.AdminPassword, o.ComposeFile)
	if err != nil {
		return nil, subject, fmt.Errorf("resolve admin password: %w", err)
	}

	client := newAPIClient(o.APIBase, o.AnalyzeTimeout)
	if err := client.login(o.AdminEmail, resolvedPassword); err != nil {
		return nil, subject, err
	}
	log.Printf("eval-harness: logged in as %s", o.AdminEmail)

	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	fingerprint := "eval-harness-fp-" + runID

	gk, err := generateCSR(fingerprint)
	if err != nil {
		return nil, subject, err
	}
	enrollToken, err := client.createEnrollmentToken()
	if err != nil {
		return nil, subject, err
	}
	clusterID, pollToken, err := client.enrollCluster(enrollToken, gk.csrPEM, fingerprint, "eval-harness-cluster-"+runID)
	if err != nil {
		return nil, subject, err
	}
	log.Printf("eval-harness: enrolled cluster %s (pendingApproval)", clusterID)
	if o.Cleanup {
		defer cleanupStackRun(o.ComposeFile, clusterID)
	} else {
		log.Printf("eval-harness: -stack-cleanup=false — cluster %s and its incidents are being LEFT BEHIND in the running stack", clusterID)
	}

	if err := client.acceptCluster(clusterID); err != nil {
		return nil, subject, err
	}
	certPEM, caPEM, err := client.pollForCert(pollToken, 20*time.Second)
	if err != nil {
		return nil, subject, err
	}
	log.Printf("eval-harness: certificate issued for cluster %s", clusterID)

	fa, err := dialFakeAgent(o.TunnelAddr, o.TunnelServerName, []byte(certPEM), gk.keyPEM, caPEM, 10*time.Second)
	if err != nil {
		return nil, subject, err
	}
	defer fa.Close()

	if err := fa.sendInitialInventory(); err != nil {
		return nil, subject, err
	}
	go fa.Serve()

	if err := client.waitForClusterState(clusterID, "Active", 15*time.Second); err != nil {
		return nil, subject, err
	}
	log.Printf("eval-harness: cluster %s is Active (real mTLS tunnel connected)", clusterID)

	subject, stopStandIn, err := configureStackSubject(client, o)
	if err != nil {
		return nil, subject, err
	}
	defer stopStandIn()
	log.Printf("eval-harness: subject — %s", subject.Description)

	allRuns := make([][]CaseResult, 0, o.Repeat)
	for pass := 1; pass <= o.Repeat; pass++ {
		results, err := runStackPass(client, fa, o, cases, clusterID, runID, pass, subject.MeasuresRealModel)
		if err != nil {
			return nil, subject, err
		}
		allRuns = append(allRuns, results)
		if o.Repeat > 1 {
			logRunScores(pass, o.Repeat, Aggregate(results))
		}
	}
	return allRuns, subject, nil
}

// runStackPass runs the whole corpus once against the already-connected
// stack. pass distinguishes one repeat's fixture rows from the next's: every
// pass gets its own incidents, findings and fingerprints, because reusing an
// incident would mean the second analysis of it starts from a different
// state than the first — and a repeat is supposed to vary nothing but the
// subject.
func runStackPass(client *apiClient, fa *fakeAgent, o stackOptions, cases []GoldenCase, clusterID, runID string, pass int, subjectHasWorldKnowledge bool) ([]CaseResult, error) {
	results := make([]CaseResult, 0, len(cases))
	for i := range cases {
		gc := &cases[i]
		if reason := SkipReasonFor(*gc, subjectHasWorldKnowledge); reason != "" {
			results = append(results, SkipCase(*gc, reason))
			continue
		}
		fa.SetCase(gc)

		suffix := fmt.Sprintf("%s_p%d", runID, pass)
		incidentID := fmt.Sprintf("inc_eval_%s_%s", safeID(gc.ID), suffix)
		findingID := fmt.Sprintf("fnd_eval_%s_%s", safeID(gc.ID), suffix)

		if err := insertFixture(o.ComposeFile, clusterID, incidentID, findingID, suffix, *gc); err != nil {
			return nil, fmt.Errorf("case %s: insert fixture: %w", gc.ID, err)
		}
		started := time.Now()
		resp, err := postAnalyze(client, incidentID)
		if err != nil {
			return nil, fmt.Errorf("case %s: POST analyze: %w", gc.ID, err)
		}
		log.Printf("eval-harness: pass %d/%d case %s analyzed in %s (status=%s iterations=%d)",
			pass, o.Repeat, gc.ID, time.Since(started).Round(time.Second), resp.Status, resp.Iterations)
		results = append(results, ScoreCase(*gc, resp))
	}
	return results, nil
}

// configureStackSubject settles which model the hub will use for this run and
// returns the one-line description of it, having READ IT BACK rather than
// assumed it. See stackSubject for why that read-back is not belt-and-braces.
func configureStackSubject(client *apiClient, o stackOptions) (stackSubject, func(), error) {
	var subject stackSubject
	// The stand-in server, when there is one, has to stay up for every
	// analyze call the run makes — so its shutdown is returned to the caller
	// to defer, not deferred here where it would fire before the first case.
	noop := func() {}

	if o.UseConfiguredProvider {
		if o.LLMBaseURL != "" {
			return subject, noop, fmt.Errorf("-stack-use-configured-provider and -llm-base-url are mutually exclusive: one says \"do not touch the hub's provider settings\" and the other says \"overwrite them\"")
		}
		view, err := client.getLLMSettings()
		if err != nil {
			return subject, noop, err
		}
		subject, err = describeConfiguredProvider(view)
		return subject, noop, err
	}

	stop := noop
	llmBaseURL, llmModel := o.LLMBaseURL, o.LLMModel
	if llmBaseURL == "" {
		port, shutdown, err := startReasonerServer(o.Personality)
		if err != nil {
			return subject, noop, err
		}
		stop = shutdown
		llmBaseURL = fmt.Sprintf("http://%s:%d", o.LLMHost, port)
		llmModel = "eval-harness-" + o.Personality
		log.Printf("eval-harness: deterministic stand-in (personality=%s) listening, hub will reach it at %s", o.Personality, llmBaseURL)
	} else {
		log.Printf("eval-harness: pointing the hub at a REAL LLM provider: %s (model=%s)", llmBaseURL, llmModel)
	}

	if err := client.putLLMSettingsFull(llmBaseURL, llmModel, o.LLMAPIKey); err != nil {
		return subject, stop, err
	}

	// The read-back. PUT /admin/settings edits the active provider in place
	// and keeps its kind, so this write only lands if that provider is an
	// `api` one. On a `cli` hub it is silently discarded and the run would
	// otherwise be scored — and billed — against a model the report never
	// names.
	view, err := client.getLLMSettings()
	if err != nil {
		return subject, stop, err
	}
	if err := verifyProviderWriteLanded(view, llmBaseURL); err != nil {
		return subject, stop, err
	}
	if o.LLMBaseURL != "" {
		return stackSubject{
			Description:       fmt.Sprintf("stack mode (real hub/tunnel/analyze) — REAL MODEL %q at %s via the hub's api backend", view.Model, view.BaseURL),
			MeasuresRealModel: true,
		}, stop, nil
	}
	return stackSubject{
		Description: fmt.Sprintf(
			"stack mode (real hub/tunnel/analyze) — DETERMINISTIC STAND-IN (personality=%s) served to the hub's api backend at %s. "+
				"This measures whether the PROMPT and the real hub path still carry what a correct investigation needs, NOT how well any model reasons.",
			o.Personality, view.BaseURL),
		MeasuresRealModel: false,
	}, stop, nil
}

// verifyProviderWriteLanded checks that the provider the hub will actually
// use is the one this run just configured, and refuses the run when it is
// not.
//
// This is not defensive paranoia about a PUT that returned 200. PUT
// /admin/settings edits the ACTIVE ai_providers row in place and preserves
// its kind (internal/settings.UpdateActiveProvider), and
// ProviderInput.clearedForKind blanks base_url/model on a kind=cli row — so
// on a hub whose active provider is a CLI runner the write succeeds, changes
// nothing that routing consults, and every analyze call goes to the model
// behind that runner. Without this check the harness would print
// "DETERMINISTIC STAND-IN" over answers a real, billed model produced, which
// is the single most misleading output this program could generate.
func verifyProviderWriteLanded(view llmSettingsView, wantBaseURL string) error {
	if view.ProviderKind != "api" {
		return fmt.Errorf(
			"the hub's active AI provider is kind=%q (runner %s, agent=%s), so the base URL this run just set was discarded: "+
				"PUT /admin/settings edits the ACTIVE provider in place and preserves its kind. "+
				"Every analyze call would have gone to that provider while the report named a different subject. "+
				"Re-run with -stack-use-configured-provider to measure it deliberately, or activate an api-kind provider first",
			view.ProviderKind, view.CLIRunnerURL, view.CLIAgent)
	}
	if view.BaseURL != wantBaseURL {
		return fmt.Errorf("the hub read back baseUrl %q after this run set %q — refusing to score answers from a provider the report cannot name", view.BaseURL, wantBaseURL)
	}
	return nil
}

// describeConfiguredProvider turns the hub's own settings into the subject
// line, and refuses a provider that cannot actually serve an analysis.
//
// A kind=cli provider can be configured perfectly and still be unusable
// because the hub has no MCP listener — internal/api reports exactly that as
// cliBackendAvailable, "a hub-level fact the client cannot infer". Failing
// here costs one API call; failing later costs a full enrollment, a tunnel
// and a corpus of analyze calls that all error identically.
func describeConfiguredProvider(view llmSettingsView) (stackSubject, error) {
	switch view.ProviderKind {
	case "cli":
		if view.CLIRunnerURL == "" {
			return stackSubject{}, fmt.Errorf("the hub's active provider is kind=cli but has no runner URL configured")
		}
		if !view.CLIBackendAvailable {
			return stackSubject{}, fmt.Errorf(
				"the hub's active provider is kind=cli but this hub reports cliBackendAvailable=false — it has no MCP listener (ARGUS_MCP_ADDR), so every analyze call would fail. Nothing was run")
		}
		return stackSubject{
			Description: fmt.Sprintf(
				"stack mode (real hub/tunnel/analyze) — REAL MODEL via the hub's CONFIGURED cli provider: agent=%s at %s",
				view.CLIAgent, view.CLIRunnerURL),
			MeasuresRealModel: true,
			Caveats: "\n--- reading this run's third number ---\n" +
				"The harness wrote no provider configuration: these answers came from whatever\nthat runner runs. Which model, and what each analysis cost, is recorded per\nanalysis by the hub itself (analyses.model, .cost_usd, .cost_basis) — read it\nthere rather than inferring it here.\n\n" +
				"The tool-call efficiency number is NOT comparable to an offline or api-backend\nrun and nothing should be concluded from it. A cli provider does not drive the\nhub's tool loop at all (internal/llm/cli_investigator.go): the CLI runs its own\nloop and reports its own turn count, which counts different things than an\niteration of internal/llm.Investigate. The cases' iteration bands were written\nagainst the latter. Both correctness scores are unaffected — they read the root\ncause, the status and the confidence, none of which depend on turn counting.\n",
		}, nil
	case "api":
		if view.BaseURL == "" {
			return stackSubject{}, fmt.Errorf("the hub's active provider is kind=api but has no base URL configured")
		}
		return stackSubject{
			Description: fmt.Sprintf(
				"stack mode (real hub/tunnel/analyze) — REAL MODEL %q at the hub's CONFIGURED api provider %s",
				view.Model, view.BaseURL),
			MeasuresRealModel: true,
		}, nil
	default:
		return stackSubject{}, fmt.Errorf("the hub reported an AI provider kind of %q, which this harness does not know how to describe", view.ProviderKind)
	}
}

// cleanupStackRun deletes the throwaway rows this run created, so a stack
// that is also being used for something else does not slowly fill with eval
// incidents.
//
// audit_events is deliberately absent from the delete list. It is a verified
// hash chain (`argusctl audit verify` re-derives it straight against
// Postgres, with no hub involved), and deleting rows out of the middle of it
// to tidy up an eval run would break the exact property that command exists
// to prove. Audit rows naming a cluster that no longer exists are harmless;
// a broken chain is not.
//
// Failures are logged, never fatal: the scores are the point of the run, and
// losing them because a cleanup DELETE hit a foreign key would be the wrong
// trade. The cluster ID is printed on failure so the rows can be found.
func cleanupStackRun(composeFile, clusterID string) {
	sql := fmt.Sprintf(`DO $$
DECLARE cid text := '%s';
BEGIN
  DELETE FROM evidence                       WHERE cluster_id = cid;
  DELETE FROM analysis_embeddings            WHERE cluster_id = cid;
  DELETE FROM remediation_approval_decisions WHERE cluster_id = cid;
  DELETE FROM remediation_execution_attempts WHERE cluster_id = cid;
  DELETE FROM remediation_executions         WHERE cluster_id = cid;
  DELETE FROM remediation_recommendations    WHERE cluster_id = cid;
  DELETE FROM mcp_tool_call_content          WHERE cluster_id = cid;
  DELETE FROM mcp_tool_calls                 WHERE cluster_id = cid;
  DELETE FROM spend_reservations             WHERE cluster_id = cid;
  DELETE FROM timeline_events                WHERE cluster_id = cid;
  DELETE FROM incident_notifications         WHERE cluster_id = cid;
  DELETE FROM incident_tolerations           WHERE cluster_id = cid;
  DELETE FROM unattended_batch_members       WHERE cluster_id = cid;
  DELETE FROM analyses                       WHERE cluster_id = cid;
  DELETE FROM findings                       WHERE cluster_id = cid;
  DELETE FROM incidents                      WHERE cluster_id = cid;
  DELETE FROM circuit_breaker_trips          WHERE cluster_id = cid;
  DELETE FROM cluster_facts                  WHERE cluster_id = cid;
  DELETE FROM cluster_group_members          WHERE cluster_id = cid;
  DELETE FROM helm_link_declines             WHERE cluster_id = cid;
  -- token_usage and local_guardrail_snapshots are deliberately absent here:
  -- both are declared not-yet-implemented in internal/migrations/schema_coverage_test.go's
  -- notImplementedTables (nothing in the product writes either), so a DELETE against
  -- them here can never match a row. It previously tripped that test's table-usage
  -- check into falsely reporting them as implemented, which would have made the
  -- registry lie about what's actually built. Do not re-add either line speculatively;
  -- add it back only once the product itself writes to the table.
  DELETE FROM clusters                       WHERE id = cid;
END $$;
`, escapeSQL(clusterID))

	// Retried, because the last analysis's embedding is written
	// ASYNCHRONOUSLY (internal/api's Store.TriggerAsync) and can land in
	// analysis_embeddings after the delete has already passed that table,
	// leaving a foreign key pointing at a row this block is about to remove.
	// Observed on the first real run of this path. Waiting a fixed period
	// instead would be a guess; retrying is the check.
	var lastOut string
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			time.Sleep(5 * time.Second)
		}
		cmd := exec.Command("docker", "compose", "-f", composeFile, "exec", "-T", "postgres",
			"psql", "-U", "postgres", "-d", "argus", "-v", "ON_ERROR_STOP=1")
		cmd.Stdin = strings.NewReader(sql)
		out, err := cmd.CombinedOutput()
		if err == nil {
			log.Printf("eval-harness: cleaned up throwaway cluster %s and its incidents (audit rows deliberately kept: the audit hash chain must stay intact)", clusterID)
			return
		}
		lastOut = string(out)
	}
	log.Printf("eval-harness: WARNING: cleanup of throwaway cluster %s failed after 3 attempts (output: %s) — those rows are still in the stack", clusterID, lastOut)
}

// safeID is used only to build a readable fixture ID, not a security
// boundary — golden case IDs are trusted, hand-authored file content.
func safeID(id string) string {
	return strings.ReplaceAll(id, "-", "_")
}

// escapeSQL is a minimal single-quote escape for building the literal SQL
// this file's own insertFixture sends — adequate here because every value
// passed through it comes from a hand-authored, checked-in golden-case
// JSON file (trusted fixture content, the same trust level
// scripts/smoke-test.sh already places in its own inline SQL heredocs), not
// from any external or model-controlled input.
func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// insertFixture writes one golden case's incident + finding rows directly
// via `docker compose exec postgres psql`, the same technique
// scripts/smoke-test.sh's own §4b/§6/§8b/§11/§13 sections already use for
// exactly the same reason: no create API exists for incidents/findings (they
// only ever arrive via a real detector or the tunnel's Finding message), so
// this is the established way to fixture one without inventing a parallel,
// unrealistic path — the real path (internal/api/analyze.go's
// handleAnalyzeIncident) is what this harness cares about testing, and that
// handler starts from an already-persisted incident+finding regardless of
// how they got there.
func insertFixture(composeFile, clusterID, incidentID, findingID, fingerprintSuffix string, gc GoldenCase) error {
	now := time.Now().UTC().Format(time.RFC3339)
	f := gc.Finding
	// The fingerprint carries the run/pass suffix as well as the case ID.
	// Correlation keys on it (internal/gateway/finding.go), so two passes of
	// the same case sharing one fingerprint would be two occurrences of one
	// symptom rather than two independent incidents — which is exactly the
	// difference a repeat run is trying to hold constant.
	fp := "eval-" + gc.ID + "-" + fingerprintSuffix
	sql := fmt.Sprintf(`DO $$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '%s';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('%s', tid, '%s', '%s', '%s', 'Detected', '%s', '%s', %d);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('%s', tid, '%s', '%s', '0.1.0', '%s', 'v1/Pod', '%s', '%s', '%s', '%s', %d, '%s', '%s', '%s');
END $$;
`,
		escapeSQL(clusterID),
		escapeSQL(incidentID), escapeSQL(clusterID), escapeSQL(fp), escapeSQL(f.Severity), now, now, f.OccurrenceCount,
		escapeSQL(findingID), escapeSQL(clusterID), escapeSQL(f.DetectorID), escapeSQL(fp),
		escapeSQL(f.Namespace), escapeSQL(f.ObjectName), escapeSQL(f.Reason), escapeSQL(f.Message), f.OccurrenceCount, escapeSQL(f.Severity), now,
		escapeSQL(incidentID),
	)

	cmd := exec.Command("docker", "compose", "-f", composeFile, "exec", "-T", "postgres",
		"psql", "-U", "postgres", "-d", "argus", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w (output: %s)", err, string(out))
	}
	return nil
}

type analyzeAPIRootCause struct {
	Statement string `json:"statement"`
}

// analyzeAPIPlan is PG9's addition (2026-10-13 parity review) — only
// actionType is read, matching parseConclusion's offline-mode counterpart:
// this harness grades which fix was reached, never applies one.
type analyzeAPIPlan struct {
	ActionType string `json:"actionType"`
}

type analyzeAPIResponse struct {
	Status     string               `json:"status"`
	RootCause  *analyzeAPIRootCause `json:"rootCause"`
	Confidence *float64             `json:"confidence"`
	Iterations int                  `json:"iterations"`
	Plan       *analyzeAPIPlan      `json:"plan"`
}

// analyzeIncidentView is the slice of GET /incidents/{id} postAnalyze polls.
// Route (PG9) is the incident's own top-level field, set by
// internal/resolution.RouteFor before the model ever proposes anything —
// not nested under Analysis, which is why it is read here rather than added
// to analyzeAPIResponse above.
type analyzeIncidentView struct {
	State         string              `json:"state"`
	Route         *string             `json:"route"`
	Analysis      *analyzeAPIResponse `json:"analysis"`
	AnalysisError *string             `json:"analysisError"`
}

// postAnalyze starts one investigation and waits for it to land. POST
// /incidents/{id}/analyze answers 202 and the hub investigates in the
// background (PROJECT.md M1), so the analysis is read from the incident once
// it leaves Investigating — or the run's failure, from analysisError.
func postAnalyze(client *apiClient, incidentID string) (AnalyzeResponse, error) {
	if _, err := client.post(fmt.Sprintf("/api/v1/incidents/%s/analyze", incidentID), nil, nil); err != nil {
		return AnalyzeResponse{}, err
	}
	deadline := time.Now().Add(client.analyzeWait)
	var view analyzeIncidentView
	for {
		view = analyzeIncidentView{}
		if _, err := client.get(fmt.Sprintf("/api/v1/incidents/%s", incidentID), &view); err != nil {
			return AnalyzeResponse{}, err
		}
		if view.State != "" && view.State != "Investigating" {
			break
		}
		if time.Now().After(deadline) {
			return AnalyzeResponse{}, fmt.Errorf("incident %s still Investigating after %s", incidentID, client.analyzeWait)
		}
		time.Sleep(2 * time.Second)
	}
	if view.AnalysisError != nil {
		return AnalyzeResponse{}, fmt.Errorf("analysis of incident %s did not complete: %s", incidentID, *view.AnalysisError)
	}
	if view.Analysis == nil {
		return AnalyzeResponse{}, fmt.Errorf("incident %s left Investigating (%s) with no analysis", incidentID, view.State)
	}
	resp := *view.Analysis
	out := AnalyzeResponse{Status: resp.Status, Confidence: resp.Confidence, Iterations: resp.Iterations}
	if resp.RootCause != nil {
		out.RootCause = resp.RootCause.Statement
	}
	if view.Route != nil {
		out.Route = *view.Route
	}
	if resp.Plan != nil {
		out.ActionType = resp.Plan.ActionType
	}
	return out, nil
}

// logRunScores prints one repeat's two scores as it finishes, rather than
// only at the end. A real-model corpus run takes minutes per pass, and a
// progress line that shows the numbers moving is what tells the person
// watching whether the spread is worth the remaining spend.
func logRunScores(i, total int, s Scores) {
	log.Printf("eval-harness: run %d/%d — root-cause %d/%d (%.1f%%), honest-negative %d/%d (%.1f%%)",
		i, total, s.RootCauseMatched, s.RootCauseTotal, 100*s.RootCauseRate(),
		s.HonestNegativeHit, s.HonestNegativeN, 100*s.HonestNegativeRate())
}
