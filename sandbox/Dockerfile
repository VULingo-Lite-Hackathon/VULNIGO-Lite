# Sandbox image: everything untrusted runs in here, nothing else.
FROM python:3.12-slim

# The official -slim images compile CPython into /usr/local/bin and the Debian
# base ships no distro interpreter, so /usr/bin/python3 does NOT exist here.
# Every script in this repo calls the absolute path, so make it true and fail
# the build if it is not.
RUN set -eux; \
    ln -sf "$(command -v python3)" /usr/bin/python3; \
    [ -x /usr/bin/timeout ] || ln -sf "$(command -v timeout)" /usr/bin/timeout; \
    test -x /usr/bin/python3; \
    test -x /usr/bin/timeout; \
    /usr/bin/python3 -c 'import sys; print("interpreter", sys.version.split()[0])'

# pytest runs the target repository's own regression suite inside the sandbox.
RUN pip install --no-cache-dir pytest==8.3.3 && rm -rf /root/.cache

# UID 65534 (nobody) already exists in the Debian base; useradd would fail on the
# duplicate UID, so containers run as the existing unprivileged user.
COPY guard.sh /usr/local/bin/guard.sh
RUN chmod 0555 /usr/local/bin/guard.sh

WORKDIR /job
USER 65534:65534

# No ENTRYPOINT: the backend passes the full command (python /harness/...), and
# containment.sh passes --entrypoint /usr/local/bin/guard.sh explicitly.
CMD ["/usr/bin/python3", "--version"]
