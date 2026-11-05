#!/usr/bin/env bash
# Containment proof. Run this ONCE the night your sandbox works, and keep the
# recording: it is the "one containment moment" the challenge requires.
#
#   sudo bash sandbox/containment.sh
#
# Same rule the product uses: a check passes on the evidence the probe prints,
# never on an exit code alone. A missing interpreter or a docker usage error also
# produces a non-zero code, and that must not read as a victory.

set -uo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "needs root to reach the docker socket:  sudo bash $0" >&2
  exit 1
fi

IMAGE="vulnigo-sandbox:latest"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBES="${HERE}/probes"
HOST_MARKER="/tmp/vulnigo-host-marker"
LOG="${1:-/tmp/vulnigo-containment-$(date +%Y%m%d-%H%M%S).log}"

PASS=0
FAIL=0
RC=0
OUT=""

# Tighter caps than production so the whole run finishes in seconds. The limits the
# backend actually enforces are printed by: sudo vulnigo-sandbox --print-config
BASE=(--rm --network none --read-only --memory 256m --memory-swap 256m --cpus 1
      --pids-limit 128 --ulimit nofile=256:256
      --cap-drop ALL --security-opt no-new-privileges:true --stop-signal SIGKILL
      --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,size=32m
      --volume "${PROBES}:/probe:ro" --label vulnigo.job=containment --workdir /tmp)

banner() { printf '\n=== %s\n' "$1" | tee -a "${LOG}"; }
note()   { printf '    %s\n' "$1" | tee -a "${LOG}"; }

held()   { printf '    RESULT: HELD  (%s)\n' "$1" | tee -a "${LOG}"; PASS=$((PASS + 1)); }
breach() { printf '    RESULT: BREACH  (%s)\n' "$1" | tee -a "${LOG}"; FAIL=$((FAIL + 1)); }

attempt() {
  local keep="$1"; shift
  OUT="$("$@" 2>&1)"
  RC=$?
  printf '%s\n' "${OUT}" | tail -n "${keep}" | tee -a "${LOG}"
}

assert_has()   { [[ "${OUT}" =~ $1 ]]; }
assert_absent() { [[ ! "${OUT}" =~ $1 ]]; }

echo "host marker written $(date -Is)" > "${HOST_MARKER}"

banner "0. build the sandbox image"
attempt 4 docker build -t "${IMAGE}" "${HERE}"
BUILD_RC=${RC}
# Run the interpreter instead of reading the build log: BuildKit prints cached or export
# lines last, so the build's own "interpreter 3.x" line is not reliably in the output tail.
attempt 1 docker run --rm --entrypoint /usr/bin/python3 "${IMAGE}" -c 'import sys; print("interpreter", sys.version.split()[0])'
if [[ ${BUILD_RC} -eq 0 && ${RC} -eq 0 ]] && assert_has 'interpreter 3\.'; then
  held "image built, interpreter path verified by running it"
else
  breach "build or interpreter check failed (build exit ${BUILD_RC}, run exit ${RC}) -- fix this before anything else"
fi

banner "1. destroy the filesystem  ->  read-only rootfs must refuse"
attempt 5 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 60 /probe/rm_root.py
if [[ ${RC} -eq 0 ]] && assert_has 'root files still present: True' && assert_has 'destructions refused: [1-9]'; then
  held "rm refused and the container's own files survived"
else
  breach "exit ${RC}: $(printf '%s' "${OUT}" | tail -1)"
fi

banner "2. memory bomb  ->  the cap must stop it"
attempt 3 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 60 /probe/mem_bomb.py 4096
if assert_has 'survived the whole allocation'; then
  breach "allocated 4 GB inside a 256 MB container -- the cap did not hold"
elif [[ ${RC} -eq 137 ]] && assert_has 'allocated '; then
  held "cgroup OOM-killed it at exit 137"
elif [[ ${RC} -eq 1 || ${RC} -eq 2 ]] && assert_has 'allocated '; then
  held "allocation refused (exit ${RC}) before completing"
else
  breach "no evidence of the cap acting (exit ${RC})"
fi

banner "3. fork bomb  ->  pids-limit 128 must refuse new processes"
attempt 3 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 60 /probe/fork_bomb.py 500
if [[ ${RC} -eq 0 ]] && assert_has 'blocked with EAGAIN'; then
  held "process table capped; further forks returned EAGAIN"
else
  breach "exit ${RC}: $(printf '%s' "${OUT}" | tail -1)"
fi

banner "4. egress and cloud metadata  ->  --network none must have no route"
attempt 6 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 60 /probe/egress.py
if [[ ${RC} -eq 0 ]] && assert_absent 'REACHABLE'; then
  held "every target refused, including 169.254.169.254"
else
  breach "exit ${RC}: something was reachable"
fi

banner "5. infinite loop  ->  the wall clock must stop it"
attempt 2 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 5 /probe/cpu_loop.py
if [[ ${RC} -eq 124 || ${RC} -eq 137 ]] && assert_absent 'survived'; then
  held "killed at the timeout (exit ${RC})"
else
  breach "exit ${RC}: the timeout did not do its job"
fi

banner "6. boundary, reported from inside the container"
attempt 16 docker run "${BASE[@]}" --entrypoint /usr/local/bin/guard.sh "${IMAGE}" 60 /probe/selftest.py
if [[ ${RC} -eq 0 ]] && assert_has 'boundary verified' && assert_absent 'breach'; then
  held "uid, capabilities, seccomp, mounts and routes all as claimed"
else
  breach "exit ${RC}: $(printf '%s' "${OUT}" | tail -1)"
fi

banner "7. host after every attack"
if [[ -s "${HOST_MARKER}" ]]; then
  note "host marker intact: $(cat "${HOST_MARKER}")"
  held "host file untouched"
else
  breach "host marker is gone"
fi

LEFT=$(docker ps -q --filter label=vulnigo.job | wc -l | tr -d ' ')
note "containers left running with a vulnigo.job label: ${LEFT}"
[[ "${LEFT}" == "0" ]] && held "every container removed" || breach "${LEFT} containers survived"

banner "summary"
printf '    held: %s   breach: %s\n' "${PASS}" "${FAIL}" | tee -a "${LOG}"
printf '    transcript: %s\n' "${LOG}" | tee -a "${LOG}"
[[ "${FAIL}" -eq 0 ]] || exit 1
