import type { GitOpsInsightResult } from "../types";

type GitOpsCondition = NonNullable<
  NonNullable<GitOpsInsightResult["summary"]>["conditions"]
>[number];

const DRIFT_SOURCE: Record<string, string> = {
  repository: "the file in the linked repository",
  lastApplied: "the last configuration a controller applied",
  argoDiff: "what Argo CD would apply from Git",
};

const OP_WORD: Record<string, string> = {
  added: "Only live",
  removed: "Only desired",
  changed: "Differs",
};

function dash(v: string | undefined): string {
  return v && v.trim() !== "" ? v : "—";
}

/** "ComparisonError" → "Comparison error". */
function conditionWords(type: string): string {
  const words = type.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  return words.charAt(0) + words.slice(1).toLowerCase();
}

/** The condition that says what is wrong right now, when the controller
 *  reports one: an *Error condition first, then a *Warning. */
function problemCondition(
  conditions: GitOpsCondition[] | null | undefined,
): GitOpsCondition | undefined {
  const list = conditions ?? [];
  return (
    list.find((c) => /Error$/.test(c.type)) ??
    list.find((c) => /Warning$/.test(c.type))
  );
}

// What Git says versus what the cluster runs (CI-S7). The problem leads: the
// parsed failure cause when there is one, else the controller's own error
// condition (a ComparisonError while sync is Unknown), ABOVE the last
// operation's message — which can say "successfully synced" from before the
// problem began, and so is labelled as the last operation, not as the state.
// Drift is a field table with Desired and Live columns, or the reason it
// could not be computed — never an unqualified "no drift".
export function GitOpsInsightView({
  result,
  showDrift = true,
}: {
  result: GitOpsInsightResult;
  showDrift?: boolean;
}) {
  const s = result.summary;
  const failure = result.parsedFailure;
  const drift = result.drift;
  const problem = failure?.cause ? undefined : problemCondition(s?.conditions);
  // The condition that leads is not repeated in the table below it.
  const otherConditions = (s?.conditions ?? []).filter((c) => c !== problem);
  return (
    <div className="insight-stack">
      {s && (
        <>
          {failure?.cause && (
            <p className="insight-lead">
              <strong>Why it is failing:</strong> {failure.cause}
              {failure.affectedKind && failure.affectedName
                ? ` (${failure.affectedKind} ${failure.affectedName})`
                : ""}
              {failure.missingNamespace
                ? ` — namespace “${failure.missingNamespace}” does not exist`
                : ""}
              {failure.stuck && (
                <>
                  {" "}
                  <span className="badge badge-red">Stuck</span> the controller
                  has stopped retrying
                  {failure.retryCount
                    ? ` after ${failure.retryCount} attempts`
                    : ""}
                  .
                </>
              )}
            </p>
          )}
          {problem && (
            <>
              <p className="insight-lead">
                <strong>
                  {s.sync && s.sync !== "Synced" ? `Sync is ${s.sync}: ` : ""}
                  {conditionWords(problem.type)}.
                </strong>{" "}
                {problem.message}
              </p>
              {problem.action && (
                <p className="field-hint">Suggested action: {problem.action}</p>
              )}
            </>
          )}
          {s.operationMessage && (
            <div>
              <p className="field-hint">
                Last operation{s.operationPhase ? ` (${s.operationPhase})` : ""}
                {problem || failure?.cause
                  ? " — what the controller last ran, which may predate the problem above"
                  : ""}
              </p>
              <pre className="code-view code-view-wrap">
                {s.operationMessage}
              </pre>
            </div>
          )}
          <dl className="kv-list">
            <dt>Controller</dt>
            <dd>{dash(s.tool)}</dd>
            <dt>Object</dt>
            <dd>
              <code>
                {s.kind} {s.namespace ? `${s.namespace}/` : ""}
                {s.name}
              </code>
            </dd>
            <dt>Sync</dt>
            <dd>{dash(s.sync)}</dd>
            <dt>Health</dt>
            <dd>{dash(s.health)}</dd>
            <dt>Source</dt>
            <dd className="insight-mono">{dash(s.source)}</dd>
            <dt>Target revision</dt>
            <dd className="insight-mono">{dash(s.targetRevision)}</dd>
            <dt>Last revision</dt>
            <dd className="insight-mono">{dash(s.lastRevision)}</dd>
            <dt>Auto-sync</dt>
            <dd>{dash(s.autoSync)}</dd>
            {s.lastReconcile && (
              <>
                <dt>Last reconcile</dt>
                <dd>{s.lastReconcile}</dd>
              </>
            )}
          </dl>
          {s.terminating && (
            <p className="insight-note">This object is being deleted.</p>
          )}
          {otherConditions.length > 0 && (
            <div className="table-scroll">
              <table className="data-table">
                <caption className="insight-caption">Conditions</caption>
                <thead>
                  <tr>
                    <th scope="col">Type</th>
                    <th scope="col">Status</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Message</th>
                    <th scope="col">Suggested action</th>
                  </tr>
                </thead>
                <tbody>
                  {otherConditions.map((c, i) => (
                    <tr key={i}>
                      <td>{conditionWords(c.type)}</td>
                      <td>{dash(c.status)}</td>
                      <td>{dash(c.reason)}</td>
                      <td className="insight-wrap">{dash(c.message)}</td>
                      <td className="insight-wrap">{dash(c.action)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {s.conditionsTruncated && (
                <p className="insight-note">
                  More conditions exist than are shown.
                </p>
              )}
            </div>
          )}
          {s.managedResources && s.managedResources.length > 0 && (
            <details className="insight-details">
              <summary>
                Managed objects — {s.managedResources.length}
                {s.managedResourcesTotal &&
                s.managedResourcesTotal > s.managedResources.length
                  ? ` of ${s.managedResourcesTotal}`
                  : ""}
              </summary>
              {s.resourceHealthUnavailable && (
                <p className="insight-note">
                  <span className="badge badge-gray">
                    Per-resource health unavailable
                  </span>{" "}
                  This Application reports{" "}
                  <code>status.resourceHealthSource: appTree</code> — Argo CD
                  does not write per-resource health here at all when that is
                  set, and ARGUS does not call argocd-server to read it another
                  way.
                </p>
              )}
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Object</th>
                      <th scope="col">Sync</th>
                      <th scope="col">Health</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.managedResources.map((m, i) => (
                      <tr key={i}>
                        <td>
                          <code>
                            {m.kind} {m.namespace ? `${m.namespace}/` : ""}
                            {m.name}
                          </code>
                        </td>
                        <td>{dash(m.status)}</td>
                        <td>
                          {s.resourceHealthUnavailable ? (
                            <span className="text-muted">unavailable</span>
                          ) : (
                            dash(m.health)
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
          {s.history && s.history.length > 0 && (
            <details className="insight-details">
              <summary>
                History — {s.history.length}
                {s.historyTruncated ? " (more exist)" : ""}
              </summary>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Revision</th>
                      <th scope="col">Deployed at</th>
                      <th scope="col">Initiated by</th>
                      <th scope="col">Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.history.map((h, i) => (
                      <tr key={i}>
                        <td className="insight-mono">{dash(h.revision)}</td>
                        <td>{dash(h.deployedAt)}</td>
                        <td>{dash(h.initiatedBy)}</td>
                        <td>{dash(h.outcome)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </>
      )}
      {showDrift && drift && <DriftTable drift={drift} />}
      {!s && !drift && (
        <p className="empty-state">
          The agent returned no GitOps summary or drift for this object.
        </p>
      )}
    </div>
  );
}

function ControllerVerdict({
  c,
}: {
  c: NonNullable<NonNullable<GitOpsInsightResult["drift"]>["controller"]>;
}) {
  const tone =
    c.status === "Synced"
      ? "badge badge-green"
      : c.status === "OutOfSync"
        ? "badge badge-amber"
        : "badge badge-gray";
  return (
    <p className="insight-note">
      <span className={tone}>
        {c.status === "OutOfSync" ? "Out of sync" : c.status}
      </span>{" "}
      {c.controller} compares this object with Application{" "}
      <span className="insight-mono">{c.application}</span>
      {c.health ? ` · health ${c.health}` : ""}
    </p>
  );
}

export function DriftTable({
  drift,
}: {
  drift: NonNullable<GitOpsInsightResult["drift"]>;
}) {
  const entries = drift.entries ?? [];
  if (drift.unavailableReason) {
    return (
      <>
        {drift.controller && <ControllerVerdict c={drift.controller} />}
        <p className="insight-note">
          <span className="badge badge-gray">Field drift unavailable</span>{" "}
          {drift.unavailableReason}
        </p>
      </>
    );
  }
  const verdict = drift.controller ? (
    <ControllerVerdict c={drift.controller} />
  ) : null;
  if (entries.length === 0) {
    return (
      <>
        {verdict}
        <p className="empty-state">
          No differences between{" "}
          {DRIFT_SOURCE[drift.source ?? ""] ?? "the desired state"} and the live
          object.
        </p>
      </>
    );
  }
  return (
    <>
      {/* The controller's verdict and the last-applied diff can disagree (Argo
        ignores fields it was told to); both are shown, neither overrides. */}
      {verdict}
      <div className="table-scroll">
        <table className="data-table">
          <caption className="insight-caption">
            Drift — compared against{" "}
            {DRIFT_SOURCE[drift.source ?? ""] ?? "the desired state"}
          </caption>
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Difference</th>
              <th scope="col">Desired</th>
              <th scope="col">Live</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i}>
                <td className="insight-mono">{e.path}</td>
                <td>{OP_WORD[e.op] ?? e.op}</td>
                <td className="insight-mono insight-wrap">{dash(e.desired)}</td>
                <td className="insight-mono insight-wrap">{dash(e.live)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {drift.truncated && (
          <p className="insight-note">More differences exist than are shown.</p>
        )}
      </div>
    </>
  );
}
