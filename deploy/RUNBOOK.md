# Deploy runbook — Vultr VM

One reachable, locked-down Vultr VM running VULNIGO Lite, with `/health` answering and the
containment moment recorded. Do it in this order. Do not skip step 3's second-terminal test.

_Hardening steps and sandbox probes contributed by Ishaan._

## 0. Key, on your laptop

```sh
ssh-keygen -t ed25519 -f ~/.ssh/vulnigo -C "vulnigo" -N ""
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
git clone https://github.com/VULingo-Lite-Hackathon/VULNIGO-Lite.git ~/VULNIGO-Lite
cd ~/VULNIGO-Lite
ADMIN_USER=yourname bash deploy/provision.sh "ssh-ed25519 AAAA... your@email"
```

## 3. Verify the new user before you lock root out

Open a **second** terminal:

```sh
ssh -i ~/.ssh/vulnigo yourname@<IP>
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

## 4. Install the app

As root (or with `sudo`), from the checkout. Do **not** clone into `/opt/vulnigo`; setup.sh copies there.

```sh
cd ~/VULNIGO-Lite
sudo DOMAIN=your.domain.example bash deploy/setup.sh   # omit DOMAIN to serve plain HTTP on the IP
sudo nano /opt/vulnigo/.env                            # set VULTR_INFERENCE_API_KEY (backend only)
sudo systemctl restart vulnigo
curl -s http://127.0.0.1:8000/health
```

setup.sh installs Docker, gVisor (`runsc`, skip with `GVISOR=0`), builds the sandbox image from
`sandbox/`, installs the systemd service as the `vulnigo` user, Caddy (HTTPS when `DOMAIN` is set)
and the firewall. It is safe to re-run after a `git pull`.

`/health` reports whether the sandbox image is present and the enforced policy. If `sandbox` is
`false`, every test is reported **inconclusive**, never passed.

## 5. Containment proof (record this)

```sh
cd ~/VULNIGO-Lite
sudo bash sandbox/containment.sh
```

It rebuilds the image, then fires `rm -rf /`, a memory bomb, a fork bomb, egress plus the cloud
metadata address, and an infinite loop at the sandbox, runs an in-container boundary self-test,
and checks the host afterwards. Each step prints `HELD` or `BREACH` from the probe's own output,
not from exit codes alone. Done looks like `held: 9   breach: 0`.

Record this screen; it is the containment moment the challenge asks for. The transcript at
`/tmp/vulnigo-containment-*.log` is what you quote in the deck. The in-app containment probe
(shown in the command centre before any repo code runs) is the second half of the same story.

## 6. Public URL

With a domain: point its A record at the VM, then re-run `sudo DOMAIN=... bash deploy/setup.sh`.
Caddy fetches the certificate itself.

No domain yet: setup.sh already serves plain HTTP on `http://<IP>/`. For a quick HTTPS link,
`cloudflared tunnel --url http://127.0.0.1:8000` works, but that URL changes every restart, so do
not submit it.

## What done looks like

- `https://<your-domain>/health` answers JSON from a browser that isn't yours, with `"sandbox": true`
- `sudo ufw status verbose` shows 22, 80, 443 and nothing else
- `containment.sh` ends with `held: 9   breach: 0`
- `sudo docker ps --filter label=vulnigo.job` shows no leftover sandbox containers
- `sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'` reads `no` / `no`

## Security notes worth saying out loud in the demo

- Every sandbox gets `--network none`, `--read-only`, a read-only code mount, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--user 65534`, `--stop-signal SIGKILL`, a `noexec,nosuid`
  tmpfs, and memory, CPU, PID, open-file and wall-clock caps; optionally the gVisor runtime.
  Agents can only request allowlisted actions by name; they never supply a shell command.
- `--network none` also means there is no route to the cloud metadata address, so credentials
  attached to the instance are unreachable from repo code. The inference key lives only in the
  backend's `.env` and is never passed into a container.
- Honest caveat, stated before a judge finds it: the backend's service user is in the `docker`
  group so it can start sandboxes, which is root-equivalent on the host if the backend itself
  were compromised. The planned fix is a root-owned wrapper reached through one sudoers line with
  every isolation flag hardcoded (prototype in the `Ishaan-files` branch).
- Say "blast radius zero, modulo a kernel or container-runtime escape" rather than "provably
  zero". gVisor narrows that further.
