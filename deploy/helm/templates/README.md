# Helm Values Templates

Starting points for the published charts (`argus-hub-chart`, `argus-agent-chart`). Pick the folder for
how ARGUS should analyse incidents, copy `hub-values.yaml`, and replace every `CHANGE_ME`:

| Folder | Use when |
|---|---|
| `api-provider` | You have an OpenAI-compatible API endpoint; configure it in Settings after install |
| `claude-cli-runner` | The hub should run Claude Code in its CLI runner |
| `codex-cli-runner` | The hub should run Codex in its CLI runner |

`agent-values.yaml` is only for enrolling a cluster by hand; the hub's **Clusters → Enroll a cluster**
prints the full agent install for you. `docs/INSTALL.md` is the guide.
