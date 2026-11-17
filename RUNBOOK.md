# RUNBOOK — the HKU ENGG Intranet pipeline

Operating notes for the `pipeline-uat` job: how to run it, how to read a
failure, how to check a site, how to roll back.

The *design* is in [`README.md`](README.md) — the stages, the topology and the
one-time host setup. This file is the day-two document.

---

## 1. The addresses

| What | Where |
|---|---|
| Jenkins | `http://192.168.147.104:8081` |
| image registry | `http://192.168.147.104:8082` |
| Aqua console | `https://192.168.147.104:8080` |
| UAT site | `http://192.168.147.104:8097` |
| PROD site | `http://192.168.147.105:8093` |
| database | `192.168.147.103:5432` — two databases, two roles |
| pipeline repo | <https://github.com/MangoTim/pipeline-uat.git> |
| application repo | <https://github.com/MangoTim/hku-calendar.git> |

## 2. Running a build

1. Open Jenkins at `http://192.168.147.104:8081`.
2. Pick the job **`pipeline-uat`** — it is a NEW job, separate from
   `mcp-dr-pipeline` and its two drill jobs.
3. *Build Now*. The job checks out `main` of `pipeline-uat` and clones the
   application at `main` of `hku-calendar`.
4. The build runs through the scans and lands on **Manual Approval**. The
   message carries the image reference, the registry digest, the application
   commit and the UAT URL with the database it is serving.
5. Open the UAT site and try it. Only then click **Promote to PROD**.
6. After the PROD stage the build is green and the PROD site runs the same
   tag.

Re-running the pipeline overwrites UAT with the new tag. PROD keeps running
the old one until somebody approves — that is the whole point of the gate.

## 3. Checking a site

```bash
curl -s http://192.168.147.104:8097/health          # UAT  -> "ok"
curl -s http://192.168.147.104:8097/health/ready     # UAT  -> "database":"engg_intranet_uat"
curl -s http://192.168.147.105:8093/health/ready     # PROD -> "database":"engg_intranet"
```

The database name in `/health/ready` is the quickest proof that UAT and PROD
are different environments and not the same data wearing two hats.

On the hosts themselves:

```bash
ssh uat@192.168.147.104  'systemctl --user status hku-intranet-uat.service; podman images'
ssh rhai@192.168.147.105 'systemctl --user status hku-intranet.service;     podman images'
```

The image reference in `podman images` must match the tag the approval
message named.

## 4. Rolling back

PROD runs one image at a time, and the role keeps only the current one, so
rollback is a deploy of the previous tag:

```bash
cd ansible
ansible-playbook -i inventory.ini deploy.yml \
    -e intranet_target=intranet_prod \
    -e intranet_image=192.168.147.104:8082/hku-intranet:v1.1.28102612
```

Add `--check --diff` first to see what would change. The tag must still exist
in the registry on `.104` — if it was pruned, rebuild it by re-running the
pipeline at that commit.

## 5. What each gate blocks, and what it looks like

| Stage | Fails when | What you see |
|---|---|---|
| `Code Scan (secrets + dependencies)` | a secret is committed, or `bun audit` finds a HIGH/Critical CVE | the Trivy secret table, or the bun audit CVE list |
| `Build Image` | the Containerfile does not build | the podman build log |
| `Push to Registry` | the pushed digest is not the scanned digest | "digest mismatch" |
| `Image Scan` | Aqua reports the image non-compliant, or Trivy finds a CRITICAL | the Aqua scan report, or the Trivy table |
| `Deploy & Verify` | the image does not start on the CI host | the container log |
| `Deploy UAT` | the env file is missing, the port does not open, or the readiness endpoint names the wrong database | the Ansible failure, naming the path or the database |
| `Manual Approval` | nobody approves within 30 minutes | the build aborts; PROD is untouched |
| `Deploy PROD` | the same as UAT, on `.105` | the Ansible failure |

**The Aqua gate** is a policy, not a scanner bug. The assurance policy
`testing-image-assurance` controls `malware` and `root_user`. A root-running
image is reported as *Image Is Non-compliant* — which is why the Containerfile
ends with `USER bun`. To widen the policy to CVEs, edit it in the Aqua
console; the pipeline needs no change.

**The Trivy database** is downloaded on the first run (~100 MB) and then
cached in the `trivy-cache` volume. A first build is slow for that reason
only.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ansible-playbook: not found` in the build | the Jenkins container was recreated — the tools are installed into the container, not baked into the image | re-run `scripts/install-jenkins-tools.sh` inside the container (it is idempotent) |
| `Permission denied (publickey)` in the deploy stage | the SSH key is missing from the container | `podman cp ~/.ssh/id_rhai108_rsa jenkins:/var/jenkins_home/.ssh/` then `chmod 600` |
| `Environment file ... does not exist` | the site has no env file | create it on the host — see the README, *One-time setup*. It is never sent from Jenkins |
| `is serving database "engg_intranet" but this site is configured for "engg_intranet_uat"` | the env file names the wrong database | fix `DB_NAME` in the site's env file and re-run |
| `twirp error internal: Failed checking cybercenter to scanner compatibility` | the Aqua console cannot reach `cybercenter5.aquasec.com` | on `.104`: `podman network reload` (a `firewall-cmd --reload` destroys podman's CNI chains) |
| the Aqua console UI on `:8080` hangs | the same CNI-chain problem | `podman logs aqua-web`, then `podman network reload` |
| `Cannot connect to the Docker daemon` in a build step | `podman.socket` is not enabled, so the socket bind does not exist | on `.104`: `systemctl enable --now podman.socket`, then recreate the Jenkins container |
| the build hangs at *Manual Approval* | that is what the gate does | approve or abort it in the Jenkins UI |
| `Raw Scan Results directory ... has only N GB of storage` | the Aqua console's disk is full | `df -h` on `.104`, remove old tarballs, restart `aqua-web` |

## 7. The container recreated — what to redo

The Jenkins container holds things that are **not** in the image:

| Lost | How to restore |
|---|---|
| `ansible-playbook`, `python3` | `scripts/install-jenkins-tools.sh` (idempotent) |
| the SSH key | `podman cp ~/.ssh/id_rhai108_rsa jenkins:/var/jenkins_home/.ssh/` |
| the mcp-dr bare origin + git daemon | the mcp-dr repository's own `scripts/install-jenkins-tools.sh` |

The registry (`registry_data`) and the Aqua volumes are named volumes, so
they survive a container recreate. The Jenkins **home** (`jenkins_data`)
survives too — jobs, build history and credentials all come back.

## 8. The databases

Both environments use one PostgreSQL instance, so the separation is enforced
by roles and grants rather than by geography:

| | UAT | PROD |
|---|---|---|
| database | `engg_intranet_uat` | `engg_intranet` |
| role | `engg_uat` | `engg_prod` |
| source host | `192.168.147.104/32` | `192.168.147.105/32` |

`CONNECT` is revoked from `PUBLIC` on both databases and granted only to the
owning role. `pg_hba.conf` matches role, database and source host together,
and every cross-environment combination is explicitly `reject`ed.

Check it from either host:

```bash
# from .104 — allowed
psql -h 192.168.147.103 -U engg_uat -d engg_intranet_uat
# from .104 — rejected
psql -h 192.168.147.103 -U engg_uat -d engg_intranet
```

The SQL that sets this up is in [`ansible/README.md`](ansible/README.md), under
*One-time host setup — the database host*.

## 9. Where the pieces are

| | |
|---|---|
| the pipeline | [`Jenkinsfile`](Jenkinsfile) |
| the deployment | [`ansible/`](ansible/) — [its own README](ansible/README.md) |
| the picture | [`docs/diagrams/pipeline/`](docs/diagrams/pipeline/) |
| the design | [`README.md`](README.md) |
| the app | <https://github.com/MangoTim/hku-calendar.git> |
