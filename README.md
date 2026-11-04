# VULNIGO Lite

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
| Frontend | Canvas-based pixel-art command centre, SSE event stream |
| Backend | Python + FastAPI — REST plus event stream, state machine in plain code |
| Agent orchestration | LangGraph with provider adapters; Pydantic-validated structured outputs |
| Security tools | Deterministic scanner and targeted proof tests; pytest for regression |
| Sandbox | Docker, non-root, network disabled, CPU/memory/PID/time limits, read-only source plus separate writable copy |
| Storage | SQLite for state and evidence, file storage for logs and diffs |

Model output is untrusted input at every boundary. Responses are schema-validated — `finding_summary`,
`file_path`, `line_range`, `confidence`, `test_plan`, `observed_result`, `patch_diff`, `limitations` — and each
requested action maps to an allowlisted tool interface. No command runs because an agent suggested it. Red and
Blue run on different model families to reduce correlated blind spots; diversity is treated as a mitigation, not
as correctness.

## Quick start

**Prerequisites:** Docker, Python 3.11+, Node.js 20+.

```sh
git clone https://github.com/<org>/vulnigo-lite.git
cd vulnigo-lite

cp .env.example backend/.env      # model credentials live in the backend process only
docker compose up --build         # sandbox image and backend
uvicorn backend.app.main:app --reload

npm --prefix frontend install
npm --prefix frontend run dev     # command centre
```

Open the command centre, choose **Demo repository**, and pick a mode. `GET /health` confirms the backend is up.

```sh
pytest -q                         # scanner, proof test and regression suite
```

### Project structure

```
frontend/    pixel-art command centre and event stream client
backend/     FastAPI battle controller: state machine, approvals, event stream
agents/      Red, Blue, Manager and Backup agents; prompts, adapters, call budgets
sandbox/     repository intake, URL validation, container lifecycle
security/    vulnerability class, demo repository, scanner, proof and regression tests
evidence/    state and evidence store, report generation, score arithmetic
docs/        design documents, screenshots, demo script
```

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
- **Untrusted code stays contained.** No repository code runs on the application host, in any mode.
- **No fabricated demos.** If a live model call fails, the run is a clearly labelled deterministic or pre-recorded result, stated as such.
- **Cleanable by design.** Sandboxes, logs and evidence are torn down and archived after every battle and check.

## Security and authorized use

- Active exploit validation runs only against the prepared demo repository or a repository you own or are explicitly authorized to assess — locally, non-destructively, narrowly scoped.
- Repo Check reads public repositories statically and read-only; it parses repository code and does not execute it.
- VULNIGO performs no scanning or exploitation of live public targets or servers.
- Containers run non-root with restricted mounts, no host sockets, no secrets, outbound network disabled by default and strict resource limits.
- Repository URLs are validated to reject local-file, private-network and unintended schemes.
- Commands, approvals, patches, backup requests, pointer decisions and test outcomes are logged for audit.

A successful test of one vulnerability does not certify a repository as secure, and neither does a clean Repo
Check. VULNIGO Lite is a learning and validation tool, not an assurance product.

## Beyond Lite

Lite deliberately ships one vulnerability class, one complete battle loop and one Manager analysis pass rather
than a broad surface. Deferred: multiple specialised agents per team, additional vulnerability classes and
language coverage, competitive multiplayer and tournaments, progression systems such as XP and achievements,
and deployment of approved patches to real environments.

## Team

| Member | Workstream |
| --- | --- |
| Ishaan | Co-lead · agent orchestration |
| Mariam | Co-lead · frontend and command centre |
| Askeri | Backend and battle controller |
| APN | Sandbox and repository intake |
| Ahmad | Security engine |
| Sharjeel | Evidence, QA and reporting |

## License

MIT — see [LICENSE](LICENSE).
