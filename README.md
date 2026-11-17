# pipeline-uat — the HKU ENGG Intranet CI/CD pipeline

The pipeline that takes the intranet application from a commit on GitHub to a
running container on the UAT site, waits for a human to say yes, and then puts
the **same bytes** on the production site.

```
GitHub ──▶ code scan ──▶ build ──▶ push ──▶ image scan ──▶ UAT ──▶ APPROVAL ──▶ PROD
          (Trivy,      (podman)  (registry)  (Aqua +      .104:8097           .105:8093
           bun audit)                                  Trivy)  engg_intranet_uat  engg_intranet
```

---

## What is in this repository

| | |
|---|---|
| `Jenkinsfile` | the pipeline itself — every stage, in order |
| `ansible/` | what actually puts the image on a site (`ansible/README.md`) |
| `scripts/` | the one-time setup for the Jenkins agent container |
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
| `192.168.147.104` | **UAT + CI** | the intranet container on `:8097`, plus Jenkins (`:8081`), the image registry (`:8082`) and Aqua (`:8080`) |
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

| Stage | What it does | Gate |
|---|---|---|
| `Checkout` | this repository, from `MangoTim/pipeline-uat` | |
| `Fetch App Source` | clones `MangoTim/hku-calendar` at `main`, records the commit | |
| `Resolve Version` | reads `app/VERSION` → the `major.minor` of the image tag | |
| `Code Scan (secrets + dependencies)` | `trivy fs --scanners secret .` on the source, and `bun audit --audit-level=high` | **hard gate** |
| `Build Image` | `podman build` of the builder stage and the runtime stage | |
| `Push to Registry` | `podman push`, then proves the pushed digest is the scanned digest | |
| `Image Scan` | Aqua registry scan + Trivy on the library tree and on the OS packages | **hard gate** |
| `Deploy & Verify` | boots the image once on the CI host to prove it starts | |
| `Deploy UAT (Database & Application)` | Ansible → `.104:8097`, then checks the database it is connected to | |
| `Manual Approval` | a human decides whether production gets it | **human gate** |
| `Deploy PROD (Database & Application)` | Ansible → `.105:8093`, then checks the database it is connected to | |

The code scan runs **before** the build on purpose. The runtime image is
multi-stage: it ships `dist/` and `server/node_modules` but NOT the frontend
`node_modules`, so the frontend dependency tree (react, vite, xlsx,
react-router-dom, typescript) is invisible to an image scan — and `xlsx` is
bundled into `dist/assets/xlsx-*.js` as a minified chunk with no package
metadata, so no scanner can map it back to a version either. The source scan
sees the tree that the image does not.

---

## What the approval decides

UAT and PROD run the **same tag** — the one this build pushed and scanned. The
tag never changes between them. So the approval decides **whether** those exact
bytes reach production, never **which** bytes that is.

The message the human sees carries the image reference, the registry digest,
the application commit, and the UAT URL with the database it is serving:

```
  image    : 192.168.147.104:8082/hku-intranet:v1.1.17112601
  digest   : sha256:...
  app      : https://github.com/MangoTim/hku-calendar.git @ <commit>
  UAT      : http://192.168.147.104:8097/   (health ok, database engg_intranet_uat)
  PROD     : http://192.168.147.105:8093/
```

`input` is **core Jenkins** — no plugin is needed. `submitter` is deliberately
not set, so anybody with the right permission can approve.

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

1. **Jenkins, the registry and Aqua** — moved here from `.105` on 2026-11-12.
   Their volumes were copied verbatim, so the registry's repositories and the
   Jenkins jobs came across unchanged. The registry is now at
   `http://192.168.147.104:8082` and the Aqua console at
   `https://192.168.147.104`.

2. **The `aqua-console` credential** — Manage Jenkins → Credentials → (global)
   → Add Credentials. Kind: *Username with password*, ID: `aqua-console`,
   Username: `administrator`. Used by the scanner CLI's `--user/--password`.

3. **The registry must be registered in the Aqua Console** — Console →
   Registries → Add → `http://192.168.147.104:8082` (no auth).

4. **The assurance policy `testing-image-assurance`** must control `malware`
   and `root_user`. `root_user` is why the Containerfile ends with
   `USER bun`: a root-running image reports *Image Is Non-compliant* and the
   gate blocks the build.

5. **The agent container's tools** — `ansible-playbook`, `python3` and the SSH
   key `/var/jenkins_home/.ssh/id_rhai108_rsa`. The key travels with the
   `jenkins_data` volume; the tools do not, because they are installed into the
   container rather than baked into the image:

   ```bash
   podman exec jenkins bash -c 'mkdir -p /var/lib/apt/lists/partial && \
       bash /var/jenkins_home/install-jenkins-tools.sh'
   ```

   Re-run it after any container recreate. It is idempotent.

6. **The Aqua's outbound path** — the `aqua-web` console container must be
   able to reach `cybercenter5.aquasec.com`, because the console performs the
   "cybercenter ↔ scanner compatibility" check server-side. When it cannot,
   the scan fails with `twirp error internal: Failed checking cybercenter to
   scanner compatibility`. A `firewall-cmd --reload` destroys podman's CNI
   chains, so `podman network reload` afterwards.

### On the UAT host (also `192.168.147.104`)

7. **The environment file** — `/home/uat/hku-intranet/env.list`, mode 0600,
   owned by `uat`. It carries UAT's own database role and password, plus the
   Entra and SSO secrets. The full template is in `ansible/README.md`. **It is
   not a copy of the PROD file** — only the Entra/SSO secrets are shared.

   > `SSO_COOKIE_SECRET` is not optional: the server refuses to start in
   > production mode without it.

8. **Python 3.9** — the inventory pins `/usr/bin/python3.9`. RHEL 8 ships
   3.6, which ansible-core ≥ 2.15 rejects.

9. **The pipeline's SSH key** in `/home/uat/.ssh/authorized_keys`.

10. **The port open** — `firewall-cmd --permanent --add-port=8097/tcp &&
    firewall-cmd --reload && podman network reload`.

### On the database host (`192.168.147.103`)

11. **The two roles and their grants**, and the `pg_hba.conf` rules. The SQL
    is in `ansible/README.md`, under *One-time host setup — the database host*.

### On the PROD host (`192.168.147.105`)

12. **The environment file** — `/home/rhai/hku-intranet/env.list`, mode 0600,
    owned by `rhai`, carrying `DB_NAME=engg_intranet` and `DB_USER=engg_prod`.

13. **The port open** — 8093.

### The Jenkins job

14. **Create the job** — a NEW job, separate from `mcp-dr-pipeline`:

    | | |
    |---|---|
    | Definition | *Pipeline script from SCM* |
    | SCM | Git · `https://github.com/MangoTim/pipeline-uat.git` |
    | Branch | `*/main` |
    | Script Path | `Jenkinsfile` |

    The pipeline's own repository IS the pipeline: the Jenkinsfile, the Ansible
    roles and the setup script are all committed here, and the deploy stages
    run `${WORKSPACE}/ansible/deploy.yml` from it.

---

## The image tag

The image is tagged with a version, not a build counter:

```
v<major>.<minor>.<DDMMYY><NN>          e.g. v1.1.17112601
```

- `major.minor` comes from the `VERSION` file in the **application** repository.
- `DDMMYY` is the build date, pinned to Hong Kong time (the agent container
  runs UTC, the host runs America/New_York).
- `NN` is the Jenkins build number, zero padded. It is monotonic, so a tag is
  never reused and always maps back to exactly one build.

Full reference: `192.168.147.104:8082/hku-intranet:v1.1.17112601`

---

## Where things live

| | |
|---|---|
| the pipeline | [`Jenkinsfile`](Jenkinsfile) |
| the deployment | [`ansible/`](ansible/) — [its own README](ansible/README.md) |
| the picture | [`docs/diagrams/pipeline/`](docs/diagrams/pipeline/) |
| day-two notes | [`RUNBOOK.md`](RUNBOOK.md) |
| the app | <https://github.com/MangoTim/hku-calendar.git> |
| the other pipeline | <https://github.com/MangoTim/pipeline-dr.git> |

## Running it by hand

```bash
cd ansible
ansible-playbook -i inventory.ini deploy.yml \
    -e intranet_target=intranet_uat \
    -e intranet_image=192.168.147.104:8082/hku-intranet:v1.1.17112601
```

Add `--check --diff` first to see what would change.
