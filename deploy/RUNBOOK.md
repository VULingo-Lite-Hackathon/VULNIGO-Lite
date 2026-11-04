# Deploy runbook — Vultr VM

Everything here is Task 1: one reachable, locked-down machine with `/health` answering.
Do it in this order. Do not skip step 4's second-terminal test.

## 0. Key, on your laptop

```sh
ssh-keygen -t ed25519 -f ~/.ssh/vulnigo -C "ishaan-vulnigo" -N ""
cat ~/.ssh/vulnigo.pub        # paste this whole line into Vultr, then into step 2
```

## 1. Create the instance

Vultr panel → Compute → Cloud Compute.

- Ubuntu 24.04 LTS x64
- 2 vCPU / 4 GB — not 1 GB, the scanner and Docker will swap
- Region: whatever the Serverless Inference page lists; otherwise Mumbai
- SSH Key: the one from step 0 (attach it **before** Deploy Now)
- Backups: off. IPv4: on.

## 2. Provision

```sh
ssh -i ~/.ssh/vulnigo root@<IP>
# then, on the VM:
git clone https://github.com/<org>/vulnigo-lite.git /opt/vulnigo
cd /opt/vulnigo/deploy
bash provision.sh "ssh-ed25519 AAAA... your@email"
```

## 3. Verify the new user before you lock root out

Open a **second** terminal:

```sh
ssh -i ~/.ssh/vulnigo ishaan@<IP>
sudo ufw status verbose
```

If that works, close root off **for real**. Ubuntu reads drop-ins first and OpenSSH
keeps the first value it sees, so editing the main file does nothing:

```sh
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config.d/99-vulnigo.conf
sudo systemctl restart ssh
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'
```

`sshd -T` prints the **effective** settings. Trust that output, not the files. It must
read `permitrootlogin no` and `passwordauthentication no`.

Vultr's web console is the recovery route if you get this wrong.

## 4. Backend service

```sh
sudo install -d -m 755 -o root -g vulnigo /etc/vulnigo
sudo cp .env.example /etc/vulnigo/vulnigo.env && sudo chmod 640 /etc/vulnigo/vulnigo.env
sudo chown root:vulnigo /etc/vulnigo/vulnigo.env
# edit VULNIGO_INFERENCE_* only; the file must never be world-readable
bash deploy/deploy.sh
curl -s http://127.0.0.1:8000/health
sudo systemctl status vulnigo --no-pager
```

`deploy.sh` re-runs safely. It checks the import before it restarts a working service.

## 4b. Prove the inference endpoint works before you write any prompt

```sh
sudo -u vulnigo sh -c 'cd /opt/vulnigo; set -a; . /etc/vulnigo/vulnigo.env; set +a; /opt/vulnigo/.venv/bin/python -m agents.smoke'
```

It lists the models the endpoint actually offers, then makes one validated call per
role and prints tokens and latency. Exit 0 means Task 3 is over: your prompts now have
a known endpoint, known model names and a measured cost. Exit non-zero means the base
URL or the auth shape is wrong, and you want to know that today, not at 2am on Nov 8.

If it lists models but you have no model names yet, copy the exact IDs into
`VULNIGO_MODEL_RED`, `_BLUE`, `_MANAGER` in `/etc/vulnigo/vulnigo.env` and run it again.

The battle loop itself runs with no key at all, and is worth running before any of this:

```sh
python -m agents.demo_run     # 22 honesty checks, from the repo root, offline
```

`agents/README.md` says what the backend must call and what the sandbox must hand back.

## 5. Sandbox image + containment proof

```sh
sudo docker build -t vulnigo-sandbox:latest sandbox
sudo bash sandbox/containment.sh
```

Record this screen. It is the containment moment the challenge asks for, and the
transcript at `/tmp/vulnigo-containment-*.log` is what you quote in the deck.

## 6. Public URL

No domain yet, fastest route:

```sh
sudo apt install -y cloudflared   # then: cloudflared tunnel --url http://127.0.0.1:8000
```

Good for tonight and for the recording. **The URL changes on every restart** — do not
submit it. By Nov 6, point a real domain's A record at the VM and use Caddy:

```sh
sudo apt install -y caddy
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile    # edit the site name first
sudo systemctl reload caddy
```

Caddy serves `frontend/` as static files and proxies `/health`. There is no build step,
so do not install Node or a bundler to make that page work.

## What done looks like

- `https://<your-domain>/health` answers JSON from a browser that isn't yours
- `sudo ufw status verbose` shows 22, 80, 443 and nothing else
- `containment.sh` ends with `held: 9   breach: 0`
- `sudo docker ps` shows no leftover `vulnigo.*` containers
- the backend user is not in the `docker` group: `id vulnigo` proves it

## Security notes worth saying out loud in the demo

- The service user cannot run docker. It may call exactly one program,
  `/usr/local/bin/vulnigo-sandbox`, through one sudoers line. That program accepts a
  job id matching `[A-Za-z0-9_-]{1,40}`, refuses symlinked job paths and anything
  outside the jobs root, and offers two modes. Every isolation flag is a hardcoded
  constant in it, not an environment variable, so a broken or compromised backend
  cannot loosen the boundary by setting one. `sudo vulnigo-sandbox --print-config`
  prints the limits that are actually enforced, and the UI reads its numbers from
  there rather than from its own config.
- Every sandbox gets `--network=none`, `--read-only`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, `--user 65534`, `--stop-signal=SIGKILL`, and
  memory, CPU, PID, file-descriptor and wall-clock caps. The wall clock lives in
  `guard.sh` inside the image, so a repository cannot ignore it by installing its own
  signal handler.
- `--network=none` also means there is no route to the cloud metadata address, so
  credentials attached to the instance are unreachable from repo code.
- One honest caveat, stated before a judge finds it: the backend service runs with
  `NoNewPrivileges` **off**, because that setting would block the single sudo call it
  needs to start a sandbox. The container itself is unprivileged and cannot escalate.
- Say "blast radius zero, modulo a kernel local privilege escalation" rather than
  "provably zero". The first is true and impressive; the second invites a question you
  cannot answer.
