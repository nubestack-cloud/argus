import {
  CAP_ANALYSIS_READ,
  CAP_AUDIT_READ,
  CAP_CLUSTER_READ,
  CAP_CLUSTER_INSPECT,
  CAP_INCIDENT_READ,
  CAP_INCIDENT_SILENCE,
  CAP_REMEDIATION_APPROVE,
  CAP_USER_READ,
} from '../api/capabilities'

// The capability each destination's route enforces (internal/api/server.go),
// shared by the sidebar (AppShell) and the Incidents section tabs
// (IncidentsSectionTabs) so the two cannot disagree about who may open a view.
// AppShell's comment above its use explains which destinations are left out.
export const NAV_REQUIRED_CAPABILITIES: Record<string, string[]> = {
  '/search': [CAP_CLUSTER_INSPECT],
  '/clusters': [CAP_CLUSTER_READ],
  '/incidents': [CAP_INCIDENT_READ],
  // GET /api/v1/findings is gated on incident:read, not a capability of its
  // own — internal/api/findings.go explains why: a finding is the evidence an
  // incident is made of, and GET /incidents/{id} already returns findings
  // under that grant, so a separate finding:read would be a distinction with
  // no authorisation decision behind it.
  '/signals': [CAP_INCIDENT_READ],
  '/approvals': [CAP_REMEDIATION_APPROVE],
  '/tolerations': [CAP_INCIDENT_SILENCE],
  '/changes': [CAP_INCIDENT_READ, CAP_ANALYSIS_READ],
  '/audit-log': [CAP_AUDIT_READ],
  '/insights': [CAP_INCIDENT_READ, CAP_ANALYSIS_READ],
  '/users': [CAP_USER_READ],
}
