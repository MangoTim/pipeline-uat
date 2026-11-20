# pipeline-uat — the HKU ENGG Intranet CI/CD pipeline

The pipeline that takes the intranet application from a commit on GitHub to a
running container on the UAT site, and — **after a human has tested it** — the
**same bytes** on the production site.

It is **two Jenkins jobs**, not one:

```
GitHub ──▶ [ pipeline-uat ] ──▶ registry
          code scan → build → push → image scan → UAT → record the promotion
          (Trivy,     (podman)  (registry)  (Trivy   .104:8097
           bun audit)                       only)   engg_intranet_uat
                                                         │
                                    the human tests UAT  │
                                                         ▼
                              [ pipeline-prod ]  ──▶ PROD
                              load the record → verify → APPROVAL → deploy
                                                             .105:8093
                                                             engg_intranet
```

The split is the point. The UAT job **finishes** and leaves UAT running; the
human test happens *between* the two jobs — an hour later, overnight, whatever.
The PROD job is started by hand, and it promotes the exact bytes that were
tested.

---

## What is in this repository

| | |
|---|---|
| `Jenkinsfile` | the **UAT job** — every stage, in order |
| `Jenkinsfile.prod` | the **PROD job** — load the record, verify it, approve, deploy |
| `ansible/` | what actually puts the image on a site (`ansible/README.md`) |
| `scripts/` | the one-time setup for the Jenkins agent container, and the two scope scripts the scan gates use (`audit_scope.py`, `trivy_scope.py`) |
| `docs/diagrams/pipeline/` | the design picture and the builder that draws it (`docs/README.md`) |
| `RUNBOOK.md` | day-two notes — running a build, reading a failure, rolling back |

**The application is not in here.** It lives in its own repository,
[`MangoTim/hku-calendar`](https://github.com/MangoTim/hku-calendar.git), and the
`Fetch App Source` stage clones it at a pinned ref into `${WORKSPACE}/app`.
The pipeline and the code it ships are versioned independently, exactly as the
RHEL MCP pipeline does it (`MangoTim/pipeline-dr` + the app repo).

---

## The lab layout

Three tiers, three hosts.

| Host | What it is | What runs there |
|---|---|---|
| `192.168.147.103` | **the data tier** | PostgreSQL 14 — ONE instance holding TWO databases, one per environment, and one role per environment |
| `192.168.147.104` | **UAT + CI** | the intranet container on `:8097`, plus Jenkins (`:8081`) and the image registry (`:8082`) |
| `192.168.147.105` | **PROD** | the intranet container on `:8093`. Nothing else |

**Why CI sits with UAT and not with PROD.** The pipeline builds and pushes
images, which is untrusted work — it runs the application's install scripts and
third-party packages. The database is the asset that has to stay away from
untrusted work; the application host is a much smaller prize, and the PROD
container there runs as a non-root user out of a systemd unit that the pipeline
never touches. CI on the PROD box would mean a compromised build owns the
production host.

The registry is on the CI host, so UAT pulls it over loopback and PROD pulls it
over the network — the same path a real promotion takes.

> `.104` is also the DR site of the *other* demo (the RHEL MCP failover drill).
> The two projects sit on it side by side, on different ports.

---

## The stages

### Job `pipeline-uat` — build and deploy UAT

| Stage | What it does | Gate |
|---|---|---|
| `Checkout` | this repository, from `MangoTim/pipeline-uat` | |
| `Fetch App Source` | clones `MangoTim/hku-calendar` at `main`, records the commit | |
| `Resolve Version` | reads `app/VERSION` → the `major.minor` of the image tag | |
| `Code Scan (secrets + dependencies)` | `trivy fs --scanners secret .` on the source, and `bun audit --json` — both sorted by `scripts/audit_scope.py` into what ships and what is only a build tool | **hard gate** |
| `Build Image` | `podman build` of the builder stage and the runtime stage | |
| `Push to Registry` | `podman push`, then proves the pushed digest is the scanned digest | |
| `Image Scan` | Trivy only: the Containerfile's own configuration (DS0002 — the image must not run as root) and the USER of the image that was actually built, then Trivy on the library tree (sorted by `scripts/trivy_scope.py`) and on the OS packages | **hard gate** |
| `Deploy & Verify` | boots the image once on the CI host to prove it starts | |
| `Deploy UAT (Database & Application)` | Ansible → `.104:8097`, then checks the database it is connected to | |
| `Record Promotion` | writes what was deployed — image, digest, app commit, UAT endpoint — to a file under `JENKINS_HOME` | |

This job never touches production. A push to `main` starts it.

### Job `pipeline-prod` — promote what was tested

| Stage | What it does | Gate |
|---|---|---|
| `Checkout` | this repository, from `MangoTim/pipeline-uat` | |
| `Load Promotion Record` | reads the record the UAT job wrote; fails if there is none | |
| `Verify Promotion` | the tag still points at the tested bytes · UAT is still running that image · the record is not too old | **hard gate** |
| `Manual Approval` | a human decides whether production gets it | **human gate** |
| `Deploy PROD (Database & Application)` | Ansible → `.105:8093`, then checks the database it is connected to | |

This job has **no `triggers` block**, so a push can never start it. It never
builds and never pushes: the tag comes from the record.

The code scan runs **before** the build on purpose. The runtime image is
multi-stage: it ships `dist/` and `server/node_modules` but NOT the frontend
`node_modules`, so the frontend dependency tree (react, vite, xlsx,
react-router-dom, typescript) is invisible to an image scan — and `xlsx` is
bundled into `dist/assets/xlsx-*.js` as a minified chunk with no package
metadata, so no scanner can map it back to a version either. The source scan
sees the tree that the image does not.

---

## What counts as a finding

Neither `bun audit` nor Trivy can tell a **build tool** from a **delivered
package** on their own:

- `bun audit` reads the lockfile, and the lockfile holds both trees.
- Trivy reports the file it found the package in. `bun install` hoists, so
  `picomatch` sits at `app/node_modules/picomatch/package.json` whether it
  was reached through `vite` or not — the path hides the parent.

So the pipeline decides for itself, from the lockfiles, using the same rule in
both places:

| | SHIPPED — blocks the build | BUILD-ONLY — reported, does not block |
|---|---|---|
| `bun audit` | `scripts/audit_scope.py` | |
| Trivy (image) | `scripts/trivy_scope.py` | |

What each workspace ships is **not** the same:

| | what ships | why |
|---|---|---|
| frontend | its production closure | only the compiled `dist/` bundle is delivered — the frontend `node_modules` are not in the runtime image at all |
| server | its **whole** installed tree | the runtime image copies `server/` straight out of the builder, so `server/node_modules` — devDependencies included — really do reach the customer |

The match is by name **and** version, because the two workspaces can carry the
same package at different versions: `typescript` 6.0.3 is the frontend build
tool, `typescript` 5.7.2 is the copy that ships.

The one finding this currently keeps out of the way is **picomatch 4.0.7**
(`GHSA-fc5q-39xc-vjpf`, HIGH, ReDoS) — the latest release, so there is no
fixed version to install, and it is reached only through `vite`. It is printed
in both reports, every build, with the path that reaches it.

A report that cannot be read is **not** a pass: both scripts exit 2 and the
gate blocks, because "not verified" must never look like "clean". Secrets are
never scoped — a hardcoded credential is a finding wherever it is, so a secret
always blocks.

---

## The scanner: Trivy, and nothing else

The CI band buys **no commercial scanner**. Everything it runs is **Trivy**,
Apache-2.0 (`github.com/aquasecurity/trivy`), executed as a container inside
the build. The `aquasec` in `docker.io/aquasec/trivy` is the Docker Hub
**publisher namespace** for that same open-source project — its canonical home
is `ghcr.io/aquasecurity/trivy` — and `aquasec/trivy-db:2` is the open
vulnerability database. There is no console to log into, no licence, no
account and no credential.

Five checks, all of them hard gates:

| | what it looks at | what it catches |
|---|---|---|
| `trivy fs --scanners secret` | the source tree | a hardcoded credential |
| `bun audit` | the two lockfiles | a dependency advisory |
| `trivy config` | the Containerfile | **DS0002** — the last `USER` must not be `root` (HIGH) |
| `podman image inspect` | the image that was **actually built** | the same rule, against the artefact rather than the file |
| `trivy image` | the library tree and the OS packages | a CVE in something that ships |

**The one gap, stated plainly: malware.** The Trivy plugin that would have
covered it has been withdrawn upstream — its repository is gone and it is no
longer in the Trivy plugin index. That is a real reduction in coverage
against the commercial policy it replaces, and it is named here rather than
quietly dropped. If the customer needs malware scanning, it has to come from
somewhere else.

---

## The vulnerability report — one page, image and code

Every build writes **`vulnerability-report.html`** and archives it with the
other artefacts, so it is downloaded from the build page like any Jenkins
artifact. It is the open-source replacement for the console dashboard, and it
covers **more** than the dashboard did: the console showed the image only.

`scripts/build_report.py` renders it out of the scan output that is already on
disk — no second scan, no new data source:

| Section | Where the findings come from |
|---|---|
| 1. Image — OS packages of the runtime base | `trivy-os-report.json` — the CVEs in the base image the customer runs |
| 2. Image — library dependencies | `trivy-report.json` — the builder stage, which still holds the frontend dependency tree |
| 3. Image — secrets in the layers | `trivy-report.json` |
| 4. Code scan — secrets in the source tree | `trivy-secret-report.json` |
| 5. Code scan — dependency advisories | `bun-audit-root.json`, `bun-audit-server.json` |

Every row carries the package, the advisory ID, the severity, the installed and
fixed versions, the **scope** — SHIPPED or BUILD-ONLY, worked out from the
lockfiles by the same rule the gates use — the path that reaches the package
and the links. The summary table at the top says how many of each severity
each scan found, and the verdict.

**Every severity is listed**, LOW and MEDIUM included — a reader is entitled
to the whole list, and hiding the lower findings would be its own kind of
misleading. The **HIGH and CRITICAL rows are tinted**, because those are the
ones that matter, and every vulnerability table carries a **Gate** column
saying whether the finding stopped the build or was only reported. The OS
scan behind the report is deliberately *unfiltered*; the gates are not — they
still stop the build on a CRITICAL alone.

Three things are deliberate:

- **Trivy's own HTML template is not enough.** `/contrib/html.tpl` renders one
  Trivy report at a time, and it renders vulnerabilities and
  misconfigurations — but **not secrets**. The `bun audit` findings are not
  Trivy findings at all. So the page is rendered by a script instead.
- **The report is generated before the gates**, so a BLOCKED build still
  leaves a report behind to diagnose.
- **A report that cannot be written fails the build.** An unreadable report
  must never look like a clean scan — the same rule the two scope scripts
  follow.

The page says the one gap out loud as well: it does **not** cover malware.

---

## What the approval decides

UAT and PROD run the **same tag** — the one the UAT build pushed and scanned.
The tag never changes between them. So the approval decides **whether** those
exact bytes reach production, never **which** bytes that is.

The message the human sees carries the image reference, the registry digest,
the application commit, the UAT URL with the database it is serving, and the
UAT build number the bytes came from:

```
  image    : 192.168.147.104:8082/hku-intranet:v1.1.17112601
  digest   : sha256:...
  app      : https://github.com/MangoTim/hku-calendar.git @ <commit>
  UAT      : http://192.168.147.104:8097/   (health ok, database engg_intranet_uat)
  UAT build: #14   (recorded 2026-11-18T16:40:12+08:00)
  PROD     : http://192.168.147.105:8093/
```

`input` is **core Jenkins** — no plugin is needed. `submitter` is deliberately
not set, so anybody with the right permission can approve.

## The promotion record — how the two jobs talk to each other

The PROD job cannot simply be told "deploy whatever UAT has", because by the
time it runs, UAT may have been redeployed. It is told **which bytes were
tested**, and it checks that they are still the ones on offer.

The UAT job writes that down as a small `KEY=VALUE` file, after its UAT health
and database checks have passed:

```
/var/jenkins_home/promotions/intranet/uat-<UAT build number>.env
/var/jenkins_home/promotions/intranet/latest.env
```

`JENKINS_HOME` lives in the `jenkins_data` volume, so a record survives a
container recreate — the same lifetime as the jobs and the credentials.

A **file** is the carrier because the controller has no `parameterized-trigger`,
no `copy-artifact` and no `job-dsl`: the usual
`build job: 'x', parameters: [...]` is not available. Both jobs run in the
same container on the same volume, so a file under `JENKINS_HOME` does the job.

Before the gate opens, the PROD job checks three things:

| Check | What it proves | What happens if it fails |
|---|---|---|
| the digest | the tag in the registry still points at the recorded bytes | **BLOCKED** — the tag was overwritten after the UAT test |
| the UAT site | UAT is still running **that image**, not merely up | **BLOCKED** — somebody re-ran the UAT job, so the evidence is gone |
| the age | the record is not older than `MAX_AGE_HOURS` (default 72) | **BLOCKED** — re-run the UAT job, or raise the parameter |

The UAT check is the one that is easy to overlook. "UAT is up" is not the same
as "UAT is running what you tested": re-running the UAT job replaces the site
while it still answers. The PROD job asks the running container for its image
reference and compares it with the record.

---

## What separates UAT from PROD

Not just a database name:

| | UAT | PROD |
|---|---|---|
| host | `192.168.147.104` | `192.168.147.105` |
| container | `hku-intranet-uat` | `hku-intranet` |
| systemd user unit | `hku-intranet-uat.service` | `hku-intranet.service` |
| port | 8097 | 8093 |
| environment file | `/home/uat/hku-intranet/hku-intranet-uat.env` | `/home/rhai/hku-intranet/env.list` |
| database | `engg_intranet_uat` | `engg_intranet` |
| database role | `engg_uat` | `engg_prod` |
| database password | UAT's own | PROD's own |

The two databases live on the same PostgreSQL host, so the separation is
enforced by **roles and grants**, not by geography:

- `CONNECT` on each intranet database is revoked from `PUBLIC` and granted only
  to that environment's role.
- `pg_hba.conf` matches role, database and source host together, and every
  cross-environment combination is explicitly `reject`ed.

The UAT container therefore **cannot** open the PROD database, even though both
databases sit in the same PostgreSQL instance. The readiness endpoint reports
the database it is actually connected to, and the pipeline asserts that value —
so "UAT is a separate environment" is checked, not assumed.

---

## One-time setup, before the first build

Listed here rather than in a README appendix, because each one fails a build
in a way that is easy to misread.

### On the CI host (`192.168.147.104`)

1. **Jenkins and the registry** — moved here from `.105` on 2026-11-12.
   Their volumes were copied verbatim, so the registry's repositories and the
   Jenkins jobs came across unchanged. The registry is now at
   `http://192.168.147.104:8082`.

2. **Nothing to install for the scanner.** The CI band is 100% open source:
   Trivy is Apache-2.0 (`github.com/aquasecurity/trivy`) and the image it is
   run from is `docker.io/aquasec/trivy` — `aquasec` there is the Docker Hub
   **publisher namespace** for that same open-source project, not a commercial
   product. Its canonical home is `ghcr.io/aquasecurity/trivy`, and
   `aquasec/trivy-db:2` is the open vulnerability database. Neither needs a
   licence, an account or a credential, and the CI band holds none.

3. **The root-user rule** — the Containerfile ends with `USER bun`, and the
   `Image Scan` stage enforces it twice: Trivy's misconfiguration scanner
   checks the Containerfile for **DS0002** (*the last USER command should not
   be `root`*, HIGH), and the image that was actually **built** is inspected
   for its own `Config.User`. The second check is the authoritative one — a
   Containerfile that says `USER bun` but was built on a base that runs as
   root must still be caught.

4. **The agent container's tools** — `ansible-playbook`, `python3` and the SSH
   key `/var/jenkins_home/.ssh/id_rhai108_rsa`. The key travels with the
   `jenkins_data` volume; the tools do not, because they are installed into the
   container rather than baked into the image:

   ```bash
   podman exec jenkins bash -c 'mkdir -p /var/lib/apt/lists/partial && \
       bash /var/jenkins_home/install-jenkins-tools.sh'
   ```

   Re-run it after any container recreate. It is idempotent.

5. **The Trivy database and rules bundle** — downloaded on demand from
   `docker.io/aquasec/trivy-db:2` and from the checks bundle that carries the
   misconfiguration rules. Both are cached in the `trivy-cache` volume on the
   CI host, so only the first build pays for them.

### On the UAT host (also `192.168.147.104`)

6. **The environment file** — `/home/uat/hku-intranet/env.list`, mode 0600,
   owned by `uat`. It carries UAT's own database role and password, plus the
   Entra and SSO secrets. The full template is in `ansible/README.md`. **It is
   not a copy of the PROD file** — only the Entra/SSO secrets are shared.

   > `SSO_COOKIE_SECRET` is not optional: the server refuses to start in
   > production mode without it.

7. **Python 3.9** — the inventory pins `/usr/bin/python3.9`. RHEL 8 ships
   3.6, which ansible-core ≥ 2.15 rejects.

8. **The pipeline's SSH key** in `/home/uat/.ssh/authorized_keys`.

9. **The port open** — `firewall-cmd --permanent --add-port=8097/tcp &&
   firewall-cmd --reload && podman network reload`.

### On the database host (`192.168.147.103`)

10. **The two roles and their grants**, and the `pg_hba.conf` rules. The SQL
    is in `ansible/README.md`, under *One-time host setup — the database host*.

### On the PROD host (`192.168.147.105`)

11. **The environment file** — `/home/rhai/hku-intranet/env.list`, mode 0600,
    owned by `rhai`, carrying `DB_NAME=engg_intranet` and `DB_USER=engg_prod`.

12. **The port open** — 8093.

### The Jenkins jobs

14. **The jobs** — two of them, both from the same repository, both separate
    from `mcp-dr-pipeline`:

    | | `pipeline-uat` | `pipeline-prod` |
    |---|---|---|
    | Definition | *Pipeline script from SCM* | *Pipeline script from SCM* |
    | SCM | Git · `https://github.com/MangoTim/pipeline-uat.git` | the same |
    | Branch | `*/main` | the same |
    | Script Path | `Jenkinsfile` | `Jenkinsfile.prod` |
    | Trigger | `githubPush()` — a push starts it | **none** — a human starts it |
    | Parameters | none | `PROMOTION_ID` (default `latest`), `MAX_AGE_HOURS` (default `72`) |

    The pipeline's own repository IS the pipeline: the Jenkinsfiles, the
    Ansible roles and the setup script are all committed here, and the deploy
    stages run `${WORKSPACE}/ansible/deploy.yml` from it.

    `pipeline-uat` was created on 2026-11-12. **No credential has to be filled
    in by hand before the first build** — the scanner is open source and needs
    none. (An `aqua-console` credential may still exist on the controller for
    the *other* project that shares it, the `aqua-demo` job; this pipeline
    does not use it.)

    The `pipeline-prod` job is created the same way: *New Item → Pipeline →
    name `pipeline-prod` → Definition: Pipeline script from SCM → Git
    `https://github.com/MangoTim/pipeline-uat.git` → Branch `*/main` → **Script
    Path: `Jenkinsfile.prod`** → Save*. Its two parameters are declared in the
    Jenkinsfile, and are also added to the job configuration so that
    *Build with Parameters* works from the very first run.

---

## The webhook

The pipeline does not have to be started from the Jenkins UI. The Jenkinsfile
declares

```groovy
triggers {
    githubPush()
}
```

and the job is a *Pipeline script from SCM* whose SCM is
`https://github.com/MangoTim/pipeline-uat.git`. The GitHub plugin matches an
incoming push against the job's SCM, so **a push to `main` of this repository
starts the run** — no button to press.

Only `pipeline-uat` carries the trigger. `pipeline-prod` has no `triggers`
block at all, so the plugin never starts it from a push — even though both
jobs share the same SCM. Production moves only when a person starts it.

Two things had to be in place for that to work:

| | |
|---|---|
| a GitHub server in Jenkins | *Manage Jenkins → System → GitHub* — the API URL `https://api.github.com`, "Manage hooks" on, and a credential whose password is the personal access token. Without it the plugin has nowhere to look and the delivery is dropped. |
| a hook on the repository | the GitHub side: a `web` hook on `MangoTim/pipeline-uat`, `push` events, pointing at Jenkins' `/github-webhook/` endpoint |

The delivery has to reach Jenkins from the internet, and Jenkins lives on a
private LAN. The hook URL is therefore a tunnel. **A quick Cloudflare tunnel
is the URL used here**, and that has one sharp edge worth knowing before a
demo: a quick tunnel has no uptime guarantee and its hostname changes every
time it is restarted, so after a restart the hook has to be pointed at the new
hostname.

For a permanent URL, use a *named* Cloudflare tunnel — it is free and gives
a stable `*.cfargotunnel.com` hostname — or give ngrok a second domain. The
ngrok account on the demo host cannot: it is on the free plan, which allows
exactly one reserved domain, and that one is already serving the public
demo.

---

## The image tag

The image is tagged with a version, not a build counter:

```
v<major>.<minor>.<DDMMYY><NN>          e.g. v1.1.17112601
```

- `major.minor` comes from the `VERSION` file in the **application** repository.
- `DDMMYY` is the build date, pinned to Hong Kong time (the agent container
  runs UTC, the host runs America/New_York).
- `NN` is the UAT job's build number, zero padded. It is monotonic, so a tag is
  never reused and always maps back to exactly one **UAT** build.

Full reference: `192.168.147.104:8082/hku-intranet:v1.1.17112601`

**The PROD job never mints a tag.** Build numbers are per job, so
`pipeline-uat #1` and `pipeline-prod #1` on the same day would mint the *same*
tag — `v1.1.<DDMMYY>01` — for *different* bytes, and the second push would
silently overwrite the first in the registry. The PROD job therefore only ever
reads the registry: its tag and its digest come from the promotion record.

---

## Where things live

| | |
|---|---|
| the UAT pipeline | [`Jenkinsfile`](Jenkinsfile) |
| the production pipeline | [`Jenkinsfile.prod`](Jenkinsfile.prod) |
| the deployment | [`ansible/`](ansible/) — [its own README](ansible/README.md) |
| the picture | [`docs/diagrams/pipeline/`](docs/diagrams/pipeline/) |
| day-two notes | [`RUNBOOK.md`](RUNBOOK.md) |
| the app | <https://github.com/MangoTim/hku-calendar.git> |
| the other pipeline | <https://github.com/MangoTim/pipeline-dr.git> |

## Running it by hand

### The pipeline

The UAT job starts on a push to `main`, or by hand from the Jenkins UI
(*Build Now* on `pipeline-uat`). The PROD job is started by hand only
(*Build with Parameters* on `pipeline-prod`) — `PROMOTION_ID` defaults to
`latest`, which promotes the most recent UAT run.

### The deployment

To put an image on a site without running the pipeline at all:

```bash
cd ansible
ansible-playbook -i inventory.ini deploy.yml \
    -e intranet_target=intranet_uat \
    -e intranet_image=192.168.147.104:8082/hku-intranet:v1.1.17112601
```

Add `--check --diff` first to see what would change.
