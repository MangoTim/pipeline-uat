# RUNBOOK — the HKU ENGG Intranet pipeline

Operating notes for the two jobs: how to run them, how to read a failure, how
to check a site, how to roll back.

The *design* is in [`README.md`](README.md) — the stages, the topology and the
one-time host setup. This file is the day-two document.

---

## 1. The addresses

| What | Where |
|---|---|
| Jenkins | `http://192.168.147.104:8081` |
| image registry | `http://192.168.147.104:8082` |
| scanner | Trivy, Apache-2.0, run in the build — no console, no account |
| UAT site | `http://192.168.147.104:8097` |
| PROD site | `http://192.168.147.105:8093` |
| database | `192.168.147.103:5432` — two databases, two roles |
| pipeline repo | `git@192.168.147.52:hku/pipeline_uat.git` (self-hosted GitLab) |
| application repo | `git@192.168.147.52:hku/hku_intranet.git` (self-hosted GitLab) |

## 2. Running a build

### The UAT job

1. Open Jenkins at `http://192.168.147.104:8081`.
2. Pick the job **`pipeline-uat`** — it is a NEW job, separate from
   `mcp-dr-pipeline` and its two drill jobs.
3. *Build Now*. The job checks out `main` of `hku/pipeline_uat` and clones the
   application at the pinned ref of `hku/hku_intranet`.

   A push to `main` of `pipeline-uat` starts the same run without the button —
   the job's `pollSCM` trigger notices within five minutes.
4. The build runs through the scans, deploys UAT, writes the promotion
   record and **ends there**. Nothing was deployed to production.
5. Open the UAT site — `http://192.168.147.104:8097` — and try it. This is
   the human test, and there is no clock on it: it can take an hour or a day.

### The production job

6. When the UAT test passes, open the job **`pipeline-prod`** and press
   **Build with Parameters**.
7. Leave `PROMOTION_ID` at `latest` to promote the most recent UAT run, or
   set it to `uat-<build number>` to promote a specific earlier one. Leave
   `MAX_AGE_HOURS` at `72`.
8. The job loads the record and runs its three checks. If any of them fails,
   it stops and says why — nothing is deployed.
9. The approval message carries the image reference, the registry digest, the
   application commit, the UAT URL with the database it is serving, and the
   UAT build number. Click **Promote to PROD**.
10. After the PROD stage the build is green and the PROD site runs the same
    tag.

Re-running the UAT job overwrites UAT with the new tag and records it as the
newest promotion. PROD keeps running the old one until somebody approves —
that is the whole point of the gate.

**A push never starts the PROD job.** It has no trigger at all.

### The notification

Both jobs end with an `emailext` step, so the promotion is announced by mail:
`✅ PROD promotion #<n> PASSED` with the image, the digest and the UAT build
it came from, and `❌ PROD promotion #<n> FAILED` with the console link.

The controller on `.104` has **no mail relay of its own** (and no entitlement
to install one), so the mail account is pointed straight at the corporate MX:

| Manage Jenkins → Extended E-mail Notification | |
|---|---|
| SMTP server | `systex.com.hk` |
| SMTP port | `25` |
| credentials | **none** — the MX accepts mail from the lab without authentication |
| SSL / TLS | off |

The **from** address must look like a real address or the MX refuses it with
`501 Bad sender address syntax`; the plugin builds it from the admin address
and the `@systex.com.hk` suffix, so **Manage Jenkins → System → Jenkins
Location → System Admin E-mail address** must be `tim.wong@systex.com.hk`.

A healthy send looks like this in the build log:

```
Sending email to: tim.wong@systex.com.hk
MAIL FROM:<tim.wong@systex.com.hk>
250 2.0.0 Ok: queued as 46A8A11FB0B
DEBUG SMTP: message successfully delivered to mail server
```

## 3. Checking a site

```bash
curl -s http://192.168.147.104:8097/health              # UAT  -> {"status":"ok","db":"ok"}
curl -s http://192.168.147.104:8097/health/ready         # UAT  -> {"status":"ok","db":"ok","database":"engg_intranet_uat"}
curl -s http://192.168.147.105:8093/health/ready         # PROD -> {"status":"ok","db":"ok","database":"engg_intranet"}
```

The database name in `/health/ready` is the quickest proof that UAT and
PROD are different environments and not the same data wearing two hats.

`/health/ready` is **anonymous** — it answers 200 with the database name when
the database answers, and 503 with the same name plus the error when it does
not, which is exactly what the deployment gate reads. `/api/db/connection`
also names the database but is an **admin** page: it answers `401` to an
anonymous probe, so it is for the browser and not for a script.

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

**The PROD job cannot do this for you.** It never builds and never mints a
tag, so it can only promote a tag that already exists — which is exactly
what a rollback needs. Point it at the old tag with `PROMOTION_ID`, or deploy
it by hand as above. Rolling back through the pipeline means going back to
the *UAT* job and re-running it at the old commit, which is slower but
re-gates the old code; the direct deploy above is the quick path.

## 5. What each gate blocks, and what it looks like

### Job `pipeline-uat`

| Stage | Fails when | What you see |
|---|---|---|
| `Code Scan (secrets + dependencies)` | a secret is committed, or `bun audit` finds a HIGH/Critical CVE | the Trivy secret table, or the bun audit CVE list |
| `Build Image` | the Containerfile does not build | the podman build log |
| `Push to Registry` | the pushed digest is not the scanned digest | "digest mismatch" |
| `Image Scan` | Trivy finds a HIGH/CRITICAL misconfiguration in the Containerfile, the built image runs as root, Trivy finds a CRITICAL, or the vulnerability report cannot be written | the Trivy config table, the `image user:` line, the Trivy table, or the report error |
| `Deploy & Verify` | the image does not start on the CI host | the container log |
| `Deploy UAT` | the env file is missing, the port does not open, or the readiness endpoint names the wrong database | the Ansible failure, naming the path or the database |
| `Record Promotion` | the promotion directory cannot be written | the mkdir/cp failure |

### Job `pipeline-prod`

| Stage | Fails when | What you see |
|---|---|---|
| `Load Promotion Record` | there is no record for that `PROMOTION_ID` | "No UAT promotion has been recorded — run the `pipeline-uat` job first" |
| `Verify Promotion` (digest) | the tag in the registry no longer points at the recorded digest | "the tag no longer points at the recorded digest" |
| `Verify Promotion` (UAT) | UAT is down, or is running a different image | "UAT is no longer running the tested image" |
| `Verify Promotion` (age) | the record is older than `MAX_AGE_HOURS` | "the promotion record is N hours old, and the limit is M" |
| `Manual Approval` | nobody approves within 12 hours | the build aborts; PROD is untouched |
| `Deploy PROD` | the same as UAT, on `.105` | the Ansible failure |

**The root-user gate** is enforced twice, and both checks are Trivy:

1. `trivy config` reads the **Containerfile** and reports **DS0002** — *the
   last USER command should not be `root`* — at HIGH severity.
2. `podman image inspect` reads the **USER of the image that was actually
   built** and pushed. This is the authoritative check: a Containerfile that
   says `USER bun` but was built on a base that runs as root must still be
   caught, and only the built image can tell us that.

That is why the Containerfile ends with `USER bun`. The check is a rule about
the artefact, not about a policy file: there is no console to log into and no
licence to buy. To widen it, change the `--severity` on the `trivy config`
call — the pipeline needs no other change.

**The one thing this pipeline does NOT check: malware.** The Trivy malware
plugin that would have covered it has been withdrawn upstream — its repository
is gone and it is no longer in the Trivy plugin index. Stated plainly rather
than quietly dropped: this is a real reduction in coverage, and if the customer
asks for malware scanning it has to come from somewhere else.

**The Trivy database** is downloaded on the first run (~100 MB) and then
cached in the `trivy-cache` volume. A first build is slow for that reason
only. The *misconfiguration* rules — the checks bundle, which carries DS0002 —
are downloaded separately and cached in the same volume.

**The vulnerability report** — every build writes `vulnerability-report.html`
and archives it with the other artefacts, so it is downloaded from the build
page like any Jenkins artifact. It is one page with five sections: the image's
OS packages, the image's libraries, the image's secrets, the source tree's
secrets and the dependency advisories — the image **and** the code together.
`scripts/build_report.py` renders it from the scan output that is already on
disk, so it costs no extra scan. It is generated *before* the gates, so a
blocked build still leaves one behind to diagnose, and a report that cannot be
written **fails the build** — an unreadable report must never look like a
clean scan. The same rule the two scope scripts follow.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ansible-playbook: not found` in the build | the Jenkins container was recreated — the tools are installed into the container, not baked into the image | re-run `scripts/install-jenkins-tools.sh` inside the container (it is idempotent) |
| `Permission denied (publickey)` in the deploy stage | the SSH key is missing from the container | `podman cp ~/.ssh/id_rhai108_rsa jenkins:/var/jenkins_home/.ssh/` then `chmod 600` |
| `Environment file ... does not exist` | the site has no env file | create it on the host — see the README, *One-time setup*. It is never sent from Jenkins |
| `is serving database "engg_intranet" but this site is configured for "engg_intranet_uat"` | the env file names the wrong database | fix `DB_NAME` in the site's env file and re-run |
| `twirp error internal: Failed checking cybercenter to scanner compatibility` | the *other* project's Aqua console (the `aqua-demo` job) cannot reach `cybercenter5.aquasec.com` — this pipeline does not use it | on `.104`: `podman network reload` (a `firewall-cmd --reload` destroys podman's CNI chains) |
| `unknown flag: --scanners` in a Trivy step | `trivy config` has no `--scanners` flag — it is an `image`/`fs` flag | remove `--scanners misconfig` from the `trivy config` call |
| `BLOCKED: the runtime image runs as root` | the built image's `Config.User` is empty or `root` | add `USER <non-root>` to the runtime stage of the Containerfile, before `CMD` |
| `Cannot connect to the Docker daemon` in a build step | `podman.socket` is not enabled, so the socket bind does not exist | on `.104`: `systemctl enable --now podman.socket`, then recreate the Jenkins container |
| the build hangs at *Manual Approval* | that is what the gate does — but it is the **PROD** job that has the gate | approve or abort it in the Jenkins UI, on `pipeline-prod` |
| `No UAT promotion has been recorded` | the PROD job found no record for that `PROMOTION_ID` | run the `pipeline-uat` job, or check `latest.env` under `/var/jenkins_home/promotions/intranet/` on the controller |
| `the tag no longer points at the recorded digest` | somebody re-pushed that tag after the UAT test | re-run the UAT job, then promote the new record |
| `UAT is no longer running the tested image` | the UAT job was re-run after the human tested it | test UAT again, then promote the newest record |
| `Raw Scan Results directory ... has only N GB of storage` | the *other* project's Aqua console disk is full — this pipeline does not use it | `df -h` on `.104`, remove old tarballs, restart `aqua-web` |
| `SMTP connection error while sending email` in the post stage | the mail account points at `127.0.0.1`, and `.104` has no relay | set the SMTP server to `systex.com.hk`, port `25`, no credentials — see *The notification* in section 2 |
| `501 Bad sender address syntax` | the from address is not a real address | set *Jenkins Location → System Admin E-mail address* to `tim.wong@systex.com.hk` |
| `535 ... authentication failed` | the mail account is trying to authenticate | clear the credentials on the mail account — the MX accepts the lab without authentication |

## 7. The container recreated — what to redo

The Jenkins container holds things that are **not** in the image:

| Lost | How to restore |
|---|---|
| `ansible-playbook`, `python3` | `scripts/install-jenkins-tools.sh` (idempotent) |
| the SSH key | `podman cp ~/.ssh/id_rhai108_rsa jenkins:/var/jenkins_home/.ssh/` |
| the mcp-dr bare origin + git daemon | the mcp-dr repository's own `scripts/install-jenkins-tools.sh` |

The registry (`registry_data`) and the Trivy cache (`trivy-cache`) are named
volumes, so they survive a container recreate. The Jenkins **home**
(`jenkins_data`) survives too — jobs, build history and credentials all come
back, and so do the promotion records, which live under
`/var/jenkins_home/promotions/intranet/`.

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
| the UAT pipeline | [`Jenkinsfile`](Jenkinsfile) |
| the production pipeline | [`Jenkinsfile.prod`](Jenkinsfile.prod) |
| the promotion records | `/var/jenkins_home/promotions/intranet/` on the controller — `uat-<n>.env` and `latest.env` |
| the deployment | [`ansible/`](ansible/) — [its own README](ansible/README.md) |
| the picture | [`docs/diagrams/pipeline/`](docs/diagrams/pipeline/) |
| the design | [`README.md`](README.md) |
| the app | `git@192.168.147.52:hku/hku_intranet.git` |
