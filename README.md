# VULNIGO LITE

**Gamified repository security — watch AI attack and defend a codebase, join a side yourself, or ask for an honest check of your own.**

VULNIGO Lite is a human-in-the-loop security environment built around one refusal: an AI agent's claim is not
evidence. Submit a GitHub repository and a Red Agent investigates it, proposes a weakness with a file, line range
and data flow, and runs a bounded validation test inside a disposable sandbox. A Blue Agent explains the root
cause and proposes the smallest relevant patch. You approve or reject that patch. An independent retest — the
original test plus regression checks — then decides what actually happened.

Verdicts come from recorded test results and source locations, never from a model's confidence. A retest that
could not run is reported as **inconclusive**, not as fixed. A repository with no hits is reported as **nothing
detected by the checks that were run**, never as secure. The final report traces every finding, status and score
back to the evidence behind it.

<!-- ![VULNIGO Lite command centre](docs/images/command-centre.png) -->

> **Hackathon:** Vultr Agent Rush (lablab.ai), Challenge 1 — *Blast Radius Zero*. Submission deadline
> 9 Nov 2026, 04:00 PKT.

---

## Project status — where we stand (updated 4 Nov 2026)

| Area | Status | Notes |
| --- | --- | --- |
| Repo intake + URL validation | ✅ Done | Only `https://github.com/<owner>/<repo>` is accepted. Clone runs with hooks, submodules, symlinks and non-https protocols disabled. Commit hash is recorded. |
| Battle state machine | ✅ Done | Every transition from the blueprint (plus `MANAGER_ANALYSING`) is enforced in code. Illegal jumps such as `DEFENDING → PATCHING` raise errors. |
| Docker sandbox runner | ✅ Code done · ✅ run on a Vultr VM 2026-11-08 (Ubuntu 24.04, kernel 6.8.0-149, Docker CE 29.9.3, runc 1.5.2, gVisor runsc 20261102.0: sandbox tests pass under both runc and gVisor; local suite 218 passed) | `--network none`, nobody user, read-only root fs and code mount, caps dropped, CPU/mem/PID/time limits, optional gVisor (`runsc`). |
| Containment probe ("containment moment") | ✅ Code done · ✅ `sandbox/containment.sh` on the Vultr VM 2026-11-08 under runc and under gVisor: 9 held, 0 breaches each | Before any repo code runs, the probe tries network, DNS, writing to the source, writing to `/etc`, the Docker socket, reading env secrets and root access. The UI shows each attempt as blocked or allowed. `sandbox/containment.sh` additionally fires a fork bomb, memory bomb, `rm -rf /`, egress/metadata and infinite-loop attack at the image and records HELD/BREACH. |
| Security engine (Python: CWE-78 + CWE-22) | ✅ Done | AST taint scanners for command injection and path traversal; bounded proof harness (CWE-78: random token written to `/tmp`; CWE-22: planted token file read back via `../`); benign-input check; project pytest as regression. |
| Demo target repo (`demo_repo/`, FileDesk) | ✅ Done | Two planted bugs in `filedesk/tools.py`: command injection in `file_size()` and path traversal in `read_upload()`, plus tests that must keep passing after the fix. |
| Red / Blue / Manager / Backup agents | ✅ Done · ⏳ awaiting Vultr inference key | Use Vultr Serverless Inference (OpenAI-compatible). Without a key they run a deterministic fallback, labelled as such everywhere. |
| Patch approval gate | ✅ Done | Approve, request changes (2 revisions max) or reject. `patcher.apply` refuses to run without an approval record. |
| Retest + verdicts | ✅ Done | Fixed and retested / Unresolved / Inconclusive, decided only from test runs. |
| Repo Check mode | ✅ Done | Static and read-only: 14 rule families for malicious code and likely vulnerabilities. Everything is graded Potential. |
| Pixel-art command centre | ✅ First version | Canvas rooms and agents, speech bubbles, live SSE feed, turn forms, diff approval, pointers, report modal. Needs a visual polish pass. |
| Evidence store + report + scores | ✅ Done | SQLite. Every score line cites a test or patch id. |
| Tests | ✅ 218 passing (Docker running) | `pytest tests` covers URL rejection and clone limits, the state machine, scanner/patch, the sandbox tool interface (spec validation), container cleanup and cap, and full battles. Tests marked `docker` run against the real sandbox image and skip without Docker. |
| Vultr VM deployment | ⏳ Blocked | Waiting on the Vultr API key. `deploy/setup.sh` is ready. |
| Demo video, slides, lablab submission | ⏳ To do | Needs a live public URL first. |

**Next steps:** create the Vultr VM → run `deploy/setup.sh` → add the inference key → run real sandboxed battles
end to end on the VM → UI polish → record the demo (including the containment moment) → submit.

## Built on Vultr

| Vultr service | How VULNIGO uses it |
| --- | --- |
| **Cloud Compute VM** (Ubuntu) | Runs everything: FastAPI battle controller, SQLite evidence store, Caddy (HTTPS) and the Docker daemon. It is the single control layer that every agent call and every execution passes through. |
| **Serverless Inference** (`api.vultrinference.com/v1`) | Every agent LLM call: Red (pick and explain a finding), Blue (root cause and patch), Manager (summary and Repo Check triage), Backup (coaching). Red and Blue are assigned models from different families when available. |
| **Sandbox on the VM** | A disposable Docker container per test (optionally gVisor `runsc`). Throwaway, no network, no secrets, resource-capped, and destroyed after each test. Working copies are deleted after each battle. |

---

## At a glance

- Three ways to use it: **Spectator**, **Participate** (Red or Blue), **Repo Check**
- Three coordinated agents — Red, Blue, Manager — plus an on-demand **Backup** agent for whichever side you play
- Two-round battles: **Attack**, then **Defense** with an independent retest
- Mandatory human approval gate before any patch is applied
- Evidence-based reporting: timeline, findings, patch outcome, unresolved risks, scoreboard
- A live pixel-art command centre showing every agent action as it happens
- All analysis and execution confined to a non-root, no-network, resource-limited sandbox

## The three modes

| Mode | What you do | Who works | You get |
| --- | --- | --- | --- |
| **Spectator** | Let Red and Blue fight, and keep approving the Manager's running list of pointers and the final patch. | Red, Blue, Manager | Battle report and approved pointers |
| **Participate** | Join Red or Blue and play the rounds yourself. Your team is fixed across both rounds. Press **Need Backup** when you can go no further. | You, your side's agent, Manager, an optional Backup agent | Battle report and scores |
| **Repo Check** | Submit a repository and ask whether it contains malicious code or likely vulnerabilities. No battle, no rounds, no patching. | Manager Agent, alone as analyst | Repo Check report |

Battles run two rounds. **Round 1 — Attack:** the Red Agent investigates scope, proposes an attack path and
attempts safe validation; a Blue participant follows the evidence and prepares the defense. **Round 2 —
Defense:** the Blue Agent explains the confirmed finding and proposes the patch; a Red participant stays on Red
and retries the original attack against the patched copy at retest. Teams never change mid-battle.

Repo Check findings are graded `Confirmed`, `Potential` or `Inconclusive`, each with a file and line. Most start
as `Potential`: a static read establishes that code looks dangerous, not that it is provably exploitable.

## How a battle runs

1. **Intake** — validate the GitHub URL, or select the prepared demo repository, then clone a read-only snapshot and record the commit hash and project metadata.
2. **Sandbox** — create a disposable, restricted container for all analysis and execution.
3. **Attack** — the Red Agent returns a candidate finding, a bounded sandbox-only test plan and the exact command.
4. **Finding review** — deterministic checks separate **confirmed** findings from **unconfirmed hypotheses**; nothing advances on assertion alone.
5. **Defense** — the Blue Agent receives only the findings and evidence it needs, explains root cause, and produces a reviewable diff with risks and assumptions.
6. **Approval** — you review the diff. Nothing reaches the working copy without an approval record.
7. **Retest** — the original safe test and regression checks run again; the outcome is `fixed`, `unresolved` or `inconclusive`.
8. **Report** — the Manager compiles timeline, findings, patch outcome, unresolved issues and scores from stored facts.

**Need Backup** is available to an actively participating user on either team, in either round, on your own
judgment. It summons an additional agent for your side, seeded with the active finding, code context and
conversation state, which supports that side for the rest of the battle. It never bypasses approval, never
switches sides, never leaves the sandbox, and is not offered in Spectator or Repo Check.

## Architecture

| Layer | Responsibility |
| --- | --- |
| **Presentation** | Pixel-art command centre: repository input, mode selection, agent activity, chat, Need Backup, approval dialog, results, scoreboard. |
| **Control** | Backend battle controller: state machine, routing, approvals, timeouts, retries, event stream. Every agent call and every tool execution passes through it. |
| **Services** | Agent service (Red, Blue, Manager, Backup) · security tools (scanner, proof test, diff inspection, regression suite) · sandbox service. |
| **Data** | State and evidence store: battles, repo checks, findings, patches, test runs, approvals, backup requests, pointers, logs, reports. |

Routine transitions are executed by the backend, not by a model, so the loop is deterministic and auditable;
models are called for judgment, not for bookkeeping. The frontend never calls a model directly. Agent activity
reaches the command centre over a Server-Sent Events stream with explicit `running` / `waiting` / `failed` /
`completed` states, and the UI distinguishes a live run from a clearly labelled deterministic fallback.

```
CREATED → REPOSITORY_VALIDATING → SANDBOX_READY
  SANDBOX_READY      → ATTACKING | MANAGER_ANALYSING
  ATTACKING          → FINDINGS_REVIEW | ATTACK_INCONCLUSIVE
  FINDINGS_REVIEW    → DEFENDING | NO_CONFIRMED_FINDING
  DEFENDING          → AWAITING_APPROVAL | DEFENSE_INCONCLUSIVE
  AWAITING_APPROVAL  → PATCHING | PATCH_REJECTED
  PATCHING           → RETESTING | PATCH_FAILED
  RETESTING          → COMPLETED | UNRESOLVED | INCONCLUSIVE
  MANAGER_ANALYSING  → CHECK_COMPLETED | CHECK_INCONCLUSIVE
```

`POST /battles` · `POST /battles/{id}/mode` · `POST /battles/{id}/messages` · `POST /battles/{id}/backup` ·
`POST /battles/{id}/approvals` · `GET /battles/{id}/events` · `POST /repo-checks` · `GET /repo-checks/{id}`

### Technology

| Layer | Choice |
| --- | --- |
| Frontend | Vanilla JS canvas pixel-art command centre (no build step), SSE event stream, served by the backend |
| Backend | Python + FastAPI — REST plus event stream, state machine in plain code |
| Agent orchestration | Plain async Python over an OpenAI-compatible client (Vultr Serverless Inference); Pydantic-validated structured outputs; per-battle call budget |
| Security tools | AST taint scanners and bounded proof harness (CWE-78 command injection, CWE-22 path traversal); benign-input check; project pytest for regression |
| Sandbox | Docker (optionally gVisor), non-root, network disabled, CPU/memory/PID/time limits, read-only source snapshot plus separate working copy |
| Storage | SQLite for state, evidence, diffs and test output |

Model output is untrusted input at every boundary. Responses are schema-validated — `finding_summary`,
`file_path`, `line_range`, `confidence`, `test_plan`, `observed_result`, `patch_diff`, `limitations` — and each
requested action maps to an allowlisted tool interface. No command runs because an agent suggested it. Red and
Blue run on different model families to reduce correlated blind spots; diversity is treated as a mitigation, not
as correctness.

## Quick start

**Prerequisites:** Python 3.11+. Docker is needed for real sandboxed tests (Linux; the Vultr VM).

```sh
git clone https://github.com/VULingo-Lite-Hackathon/VULNIGO-Lite.git
cd VULNIGO-Lite
pip install -r requirements.txt
cp .env.example .env                      # put VULTR_INFERENCE_API_KEY here; backend process only, never the sandbox
docker build -t vulnigo-sandbox:latest sandbox
uvicorn vulnigo.main:app --reload         # http://localhost:8000
```

Open the command centre, choose **Prepared demo repo**, and pick a mode. `GET /health` reports whether the
sandbox and Vultr inference are available. Without Docker, every test is reported as **inconclusive** (never
confirmed). Without an inference key, agents run a labelled deterministic fallback.

```sh
pytest tests -q                           # everything; the real-Docker tests skip when Docker or the image is missing
pytest tests -q -m docker                 # only the real-Docker tests: isolation, limits, whole battle (needs the image)
docker build -t vulnigo-sandbox:latest sandbox   # build the sandbox image first
```

### Deploy to a Vultr VM

On a fresh Ubuntu 22.04/24.04 Vultr Cloud Compute instance (1 vCPU / 2 GB is enough), as root:

```sh
git clone https://github.com/VULingo-Lite-Hackathon/VULNIGO-Lite.git && cd VULNIGO-Lite
DOMAIN=your.domain.example bash deploy/setup.sh   # omit DOMAIN to serve plain HTTP on the VM's IP
nano /opt/vulnigo/.env                            # set VULTR_INFERENCE_API_KEY
systemctl restart vulnigo
```

This installs Docker, gVisor, the sandbox image, a systemd service running as a dedicated user, Caddy and a firewall.
Optional first step for a locked-down VM (admin user, key-only SSH): `ADMIN_USER=you bash deploy/provision.sh "<ssh pubkey>"`.
Then record the containment moment: `sudo bash sandbox/containment.sh`. Full step-by-step: [`deploy/RUNBOOK.md`](deploy/RUNBOOK.md).

### Project structure

```
frontend/              pixel-art command centre (canvas renderer, SSE client, approval/turn/report UI)
vulnigo/main.py        FastAPI app: REST endpoints + SSE event stream, rate limiting
vulnigo/battle.py      battle controller: state machine driver, approvals, human turns, Need Backup
vulnigo/state.py       allowed state transitions
vulnigo/agents.py      Red, Blue, Manager, Backup agents; schemas, call budget, labelled fallbacks
vulnigo/llm.py         Vultr Serverless Inference client, model selection
vulnigo/intake.py      GitHub URL validation, safe clone, snapshot + working copy, cleanup
vulnigo/sandbox.py     Docker sandbox runner with allowlisted actions only
vulnigo/harness/       code that runs inside the sandbox: proof test, containment probe
vulnigo/scanner.py     CWE-78 / CWE-22 taint scanners + Repo Check rules
vulnigo/patcher.py     patch generation/validation; approval-gated apply
vulnigo/report.py      evidence-based report and score arithmetic
vulnigo/store.py       SQLite evidence store
demo_repo/             intentionally vulnerable target (FileDesk) with its own tests
deploy/                setup.sh, provision.sh (optional VM hardening), RUNBOOK.md, systemd unit
sandbox/               sandbox image, guard.sh, containment.sh + attack probes (recorded containment moment)
tests/                 test suite
```

### API

`POST /battles` · `POST /battles/{id}/mode` · `POST /battles/{id}/messages` · `POST /battles/{id}/backup` ·
`POST /battles/{id}/approvals` · `POST /battles/{id}/actions` (participant turns) ·
`POST /battles/{id}/pointers/{pid}` · `GET /battles/{id}` · `GET /battles/{id}/events` (SSE) ·
`GET /battles/{id}/report` · `POST /repo-checks` · `GET /repo-checks/{id}` · `GET /health`

## Demo walkthrough

1. Open the command centre and submit the prepared intentionally vulnerable repository; watch the sandbox come up.
2. **Repo Check** — the Manager Agent inspects it alone and flags the planted weakness with its source location. No battle has started.
3. **Spectator** — start a battle and let Red and Blue work; the Manager accumulates a list of pointers and you approve them one by one.
4. **Participate as Blue** — Red presents a vulnerability, and the candidate is not treated as confirmed until the test supports it. Blue explains root cause and proposes a patch. Press **Need Backup** to bring in a second Blue agent.
5. Review the diff and approve it explicitly; run the independent retest and show the real result — including when it is not a pass.
6. Close on the report: evidence links, unresolved risks and team scores, each traced to a recorded test run.

## What VULNIGO guarantees

- **Evidence or it didn't happen.** Every reported finding, status and score traces to a recorded test result or a `file:line`.
- **No silent changes.** Patch application never occurs without an approval record.
- **Honest vocabulary.** `Confirmed` requires a bounded test that reproduced the stated behaviour. `Inconclusive` is never presented as a pass.
- **Untrusted code runs only in a restricted container.** No repository code runs on the application host, in any mode. Docker lowers the risk; it is not an absolute guarantee, and its configuration and the host still matter (see below).
- **No fabricated demos.** If a live model call fails, the run is a clearly labelled deterministic or pre-recorded result, stated as such.
- **Cleanable by design.** Sandboxes, logs and evidence are torn down and archived after every battle and check.

## Security and authorized use

- Active exploit validation runs only against the prepared demo repository or a repository you own or are explicitly authorized to assess — locally, non-destructively, narrowly scoped.
- Repo Check reads public repositories statically and read-only; it parses repository code and does not execute it.
- VULNIGO performs no scanning or exploitation of live public targets or servers.
- Containers run non-root with restricted mounts, no host sockets, no secrets, outbound network disabled by default and strict resource limits.
- The container limits are checked by tests (`tests/test_isolation_docker.py`, `sandbox/containment.sh`) on the machine they run on. They do not prove the host kernel or Docker daemon is free of escape bugs: keep the host patched, keep `VULNIGO_ALLOW_UNSANDBOXED_DEMO` unset on shared machines, and treat the VM as the outer boundary. Raw kernel-facing sockets (`AF_ALG`, `AF_VSOCK`, `AF_PACKET`, `AF_KEY`) are blocked in the container and a test pins that; `AF_UNIX`, `AF_INET` and `AF_NETLINK` stay available to repository code, so kernel bugs reachable through them are closed only by patching the host kernel. Run untrusted repositories on the patched Linux VM; a developer machine with Docker Desktop on WSL2 needs the current Docker Desktop and WSL releases first.
- Repository URLs are validated to reject local-file, private-network and unintended schemes. Clones are capped at `MAX_REPO_MB` (50) and `CLONE_TIMEOUT` (60 s); a failed or oversized clone is deleted and the battle ends `FAILED`.
- Sandbox requests are an allowlist (`probe`, `proof`, `benign`, `regression`). A proof spec is validated before any container starts. Under gVisor the process limit is raised to at least 256, because gVisor counts its own host threads against it. At most `SANDBOX_MAX_CONTAINERS` (4) containers run at once, and a restarted backend removes leftover `sbx_` containers older than the test timeout.
- Commands, approvals, patches, backup requests, pointer decisions and test outcomes are logged for audit.

A successful test of one vulnerability does not certify a repository as secure, and neither does a clean Repo
Check. VULNIGO Lite is a learning and validation tool, not an assurance product.

## Beyond Lite

Lite deliberately ships two vulnerability classes, one complete battle loop and one Manager analysis pass rather
than a broad surface. Deferred: multiple specialised agents per team, additional vulnerability classes and
language coverage, competitive multiplayer and tournaments, progression systems such as XP and achievements,
and deployment of approved patches to real environments.

## Team

| Member | Workstream |
| --- | --- |
| Ishaan | Co-lead · agent orchestration |
| Mariam | Co-lead · frontend and command centre |
| Askeri | Backend and battle controller |
| [APN](https://github.com/GPA-N) | Sandbox and repository intake |
| Ahmad | Security engine |
| Sharjeel | Evidence, QA and reporting |

## License

MIT — see [LICENSE](LICENSE).
