# Image used for every sandboxed execution. Contains only Python + pytest; no secrets, no tools
# for networking beyond the stdlib. Runs as nobody; the backend also enforces --network none etc.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest==8.3.3 \
 && rm -rf /root/.cache
USER 65534:65534
WORKDIR /tmp
