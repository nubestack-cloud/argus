// The resource-usage charts shared by the incident page's "Resource usage"
// section and the object panel's Metrics tab (PROJECT.md AD7): one range
// picker and one grid of time-series panels over the hub's metrics answer.
// An unavailable answer renders its reason, never an empty chart that reads
// as zero.
import { TimeSeriesChart } from "../../charts/TimeSeriesChart";
import type {
  ChartAnnotation,
  ReferenceLine,
  TimeSeries,
} from "../../charts/types";
import type { MetricPanel } from "../../api/types";
import {
  stepSeconds,
  unixSeconds,
} from "../../pages/incident-detail/insightModel";

export const METRIC_RANGES = ["1h", "6h", "24h"] as const;
export type MetricRange = (typeof METRIC_RANGES)[number];

/** The part of a metrics answer the charts read; both endpoints return it. */
export interface MetricsAnswer {
  available: boolean;
  reason?: string;
  workload?: string;
  scope?: string;
  start: string;
  end: string;
  step: string;
  panels: MetricPanel[];
}

export function MetricRangePicker({
  range,
  onChange,
  unavailableReason,
}: {
  range: MetricRange;
  onChange: (r: MetricRange) => void;
  /** Set once the hub has said there is no metrics source: another window
   *  would ask the same absent Prometheus and get the same answer. */
  unavailableReason?: string;
}) {
  return (
    <div className="insight-range" role="group" aria-label="Time range">
      {METRIC_RANGES.map((r) => (
        <button
          key={r}
          type="button"
          aria-pressed={range === r}
          onClick={() => onChange(r)}
          disabled={unavailableReason !== undefined}
          title={
            unavailableReason !== undefined
              ? `Not available: ${unavailableReason}`
              : undefined
          }
        >
          {r}
        </button>
      ))}
    </div>
  );
}

export function MetricPanels({
  answer,
  annotations,
  referenceLines = {},
}: {
  answer: MetricsAnswer;
  annotations: ChartAnnotation[];
  /** Horizontal lines per panel id, e.g. a pod's request and limit on cpu and memory. */
  referenceLines?: Partial<Record<string, ReferenceLine[]>>;
}) {
  if (!answer.available) {
    return (
      <p className="insight-note">
        <span className="badge badge-gray">Not available</span>{" "}
        {answer.reason || "The hub did not say why."}
      </p>
    );
  }
  const domain = {
    minTs: unixSeconds(answer.start),
    maxTs: unixSeconds(answer.end),
  };
  return (
    <>
      {answer.workload && (
        <p className="field-hint">
          {answer.workload}
          {answer.scope ? ` — ${answer.scope}` : ""}
        </p>
      )}
      <div className="insight-chart-grid">
        {answer.panels.map((p) =>
          p.error ? (
            <div key={p.id} className="ts-chart">
              <p className="ts-chart-title">{p.title}</p>
              <p className="form-error">This query failed: {p.error}</p>
            </div>
          ) : p.series.length === 0 && p.note ? (
            <div key={p.id} className="ts-chart">
              <p className="ts-chart-title">{p.title}</p>
              <p className="empty-state">{p.note}</p>
            </div>
          ) : (
            <div key={p.id}>
              <TimeSeriesChart
                title={p.title}
                unit={p.unit}
                series={p.series.map((s): TimeSeries => ({
                  labels: s.labels,
                  dataPoints: s.points.map(([ts, v]) => ({
                    timestamp: ts,
                    value: v,
                  })),
                }))}
                annotations={annotations}
                referenceLines={referenceLines[p.id]}
                stepSeconds={stepSeconds(answer.step)}
                domain={domain}
              />
              {p.note && <p className="field-hint">{p.note}</p>}
            </div>
          ),
        )}
      </div>
    </>
  );
}
