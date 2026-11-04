READ ME FIRST

This is a READ-ONLY copy for sharing, made 2026-11-04 14:53.
The canonical folder you edit, test and commit is:
    something/vulnigo-lite/

Do not change files here. Two editable copies is how a team ends up shipping the stale
one. Make your change in vulnigo-lite/, re-run the two checks below, then re-copy.

Verify what you received (from this folder, offline, no VM/Docker/key needed):
    python -m pytest -q            -> expect 136 passed
    python -m agents.demo_run      -> expect 22/22 checks held

Read order for a teammate (READMEs are not in this copy by request):
    deploy/RUNBOOK.md   the Vultr VM steps, in sequence
    agents/README.md and README.md live only in the canonical vulnigo-lite/ folder
