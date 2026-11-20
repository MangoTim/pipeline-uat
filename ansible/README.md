# `ansible/` — deploying the intranet to UAT and to PROD

The pipeline builds the image, pushes it to the registry, scans it, and then
**stops**. This directory is what actually puts it on a site.

```
build → push → scan ──▶ deploy UAT ──▶ record ──▶ [ approval ] ──▶ deploy PROD
                          .104:8097                           .105:8093
                          db engg_intranet_uat                db engg_intranet
                          (db on .103)                        (db on .103)
```

The deploy is split across **two Jenkins jobs**. The UAT job builds, scans and
deploys UAT, then writes down what it deployed. The PROD job reads that record
back, and the approval happens inside it — so the gate is a job boundary, and
the human test is not squeezed into a suspended build.

Both sites run the **same tag** — the one the pipeline pushed and scanned. The
approval decides *whether* those exact bytes reach production, never *which*
bytes that is.

## The lab layout

Three tiers, three hosts.

| Host | What it is for the intranet | Deploy user |
|---|---|---|
| `192.168.147.103` | **the data tier** — PostgreSQL 14, holding BOTH databases. The other demo's DR site joins this host later | — |
| `192.168.147.104` | **UAT + CI** — the intranet container, and the pipeline itself (Jenkins, the image registry, Trivy). UAT pulls the image over loopback | `uat` |
| `192.168.147.105` | **PROD** — the live site only. No CI on the box: PROD pulls the image from the registry over the network | `rhai` |

CI sits with UAT rather than with PROD on purpose. The pipeline builds and
pushes images, which is untrusted work — it runs the app's install scripts and
third-party packages. The database is the asset that has to stay away from
untrusted work; the application host is a much smaller prize, and the PROD
container there runs as a non-root user out of a systemd unit that the
pipeline never touches.

The database is **not** on the UAT host. Both environments reach it over the
network, from their own host, with their own database role:

| | UAT | PROD |
|---|---|---|
| app host | `192.168.147.104` | `192.168.147.105` |
| database host | `192.168.147.103` | `192.168.147.103` |
| database | `engg_intranet_uat` | `engg_intranet` |
| role | `engg_uat` | `engg_prod` |

That is what keeps the two environments apart even though they share one
PostgreSQL instance: each role can `CONNECT` only to its own database, and
`pg_hba.conf` matches the role, the database and the source host together. The
UAT container cannot open the PROD database even if it wanted to.

> A single PostgreSQL host is a single point of failure. The DR site that
> belongs to the *other* demo joins `.103` later, which is where the standby
> replica goes.

## The house rules

Same as the RHEL MCP pipeline (`products/mcp-dr-pipeline/ansible/`):

- **No `become`, no sudo password, no root.** Each site is driven as its own
  non-root user with rootless podman.
- **systemd *user* units.** The application is supervised and starts on boot,
  but `systemctl --user` needs no privilege.
- **The secrets stay on the host.** The environment file (database password,
  Entra client secret, SSO cookie secret) is never sent through Jenkins.
  The pipeline only chooses the image; the site already knows its port and
  its database.

## One-time host setup — UAT (`192.168.147.104`, user `uat`)

`.104` used to be the DR site of the other demo. It is now the intranet's UAT
host **and** the CI host, so it needs the same treatment the other sites have
— plus the pipeline stack that moved here from `.105`.

1. **The deploy user `uat`.** A plain user, not in `wheel`:

   ```bash
   useradd -m -s /bin/bash uat
   loginctl enable-linger uat
   ```

   Lingering is what keeps the systemd *user* manager alive between SSH
   sessions, so the unit comes back after a reboot. **Done.**

2. **The environment file must exist:**

   ```
   /home/uat/hku-intranet/env.list   (mode 0600, owned by uat)
   ```

   It carries UAT's **own** values — `HOST=0.0.0.0`, `PORT=8097`,
   `NODE_ENV=production`, `DB_HOST=192.168.147.103`, `DB_NAME=engg_intranet_uat`,
   `DB_USER=engg_uat`, `DB_PASSWORD=<the UAT role's password>`, plus the
   `AZURE_*` and `SSO_*` entries from the RUNBOOK's Section 4.2 template.

   **This file is NOT a copy of the PROD one.** Only the Entra/SSO secrets are
   the same; the database role and its password are UAT's own, so the UAT
   container is never holding a credential that can open the PROD database.
   The role then derives the file the container actually reads
   (`hku-intranet-uat.env`) from this one, rewriting `PORT` and `DB_NAME`.

   > `SSO_COOKIE_SECRET` is not optional. The server refuses to start in
   > production mode without it, so it is in both files. Rotating it means the
   > sealed Entra client secret has to be re-sealed too — see the RUNBOOK.

3. **Python 3.9** — the inventory pins `/usr/bin/python3.9`, because RHEL 8
   ships 3.6 as `/usr/bin/python3` and ansible-core ≥ 2.15 will not use it.
   This host has no RHEL entitlement, so the package was installed from the
   same RPMs the other sites use (`python39`, `python39-libs`,
   `python39-pip-wheel`, `python39-setuptools-wheel`, `chkconfig`). **Done.**

4. **The pipeline's SSH key** in `/home/uat/.ssh/authorized_keys` (mode 0600).
   It is the same key the other sites use (`id_rhai108_rsa`). **Done.**

5. **Open the UAT port:**

   ```bash
   firewall-cmd --permanent --add-port=8097/tcp
   firewall-cmd --reload
   podman network reload        # a reload can drop podman's CNI chains
   ```

   Without this the UAT container starts but nothing can reach it from outside
   the host. **Done.**

6. **The CI stack that moved here from `.105`** — Jenkins (`:8081`) and the image
   registry (`:8082`). Their volumes were copied verbatim, so the registry's
   repositories and the Jenkins jobs came across unchanged. See the top-level
   README for the move itself. (The scanner needs nothing on the host at all:
   Trivy is run as a container inside the build.)

## One-time host setup — the database host (`192.168.147.103`)

PostgreSQL 14 is already running there on `0.0.0.0:5432` with the
`engg_intranet` database. Three things have to change before UAT can share it.

1. **One role per environment.** The `engg_intranet` database and its tables
   were created by the `postgres` superuser, so the ownership moves too —
   otherwise the new role could read nothing:

   ```sql
   CREATE ROLE engg_uat   LOGIN PASSWORD '<uat password>';
   CREATE ROLE engg_prod  LOGIN PASSWORD '<prod password>';

   CREATE DATABASE engg_intranet_uat OWNER engg_uat;
   ALTER DATABASE engg_intranet OWNER TO engg_prod;
   ALTER SCHEMA public OWNER TO engg_prod;      -- and engg_uat in the UAT db
   -- then, for every table / view in engg_intranet:
   ALTER TABLE public.<name> OWNER TO engg_prod;
   ```

2. **CONNECT is not PUBLIC any more.** By default every role may connect to
   every database, so the grant has to be made explicitly:

   ```sql
   REVOKE ALL ON DATABASE engg_intranet      FROM PUBLIC;
   REVOKE ALL ON DATABASE engg_intranet_uat  FROM PUBLIC;
   GRANT CONNECT, TEMPORARY ON DATABASE engg_intranet      TO engg_prod;
   GRANT CONNECT, TEMPORARY ON DATABASE engg_intranet_uat  TO engg_uat;
   ```

3. **`pg_hba.conf` — one rule per environment, ABOVE the generic one.** The
   file also carries `host all all 0.0.0.0/0 md5`, which the other demos on this
   server rely on, so it **stays**. The intranet rules go
   above it, where they are matched first:

   ```
   host  engg_intranet_uat  engg_uat   192.168.147.104/32   md5
   host  engg_intranet      engg_prod  192.168.147.105/32   md5
   host  engg_intranet_uat  engg_uat   0.0.0.0/0            reject
   host  engg_intranet_uat  engg_prod  0.0.0.0/0            reject
   host  engg_intranet      engg_uat   0.0.0.0/0            reject
   host  engg_intranet      engg_prod  0.0.0.0/0            reject
   ```

   The first two lines are the only way in; the four `reject` lines close
   every other combination — including a UAT container reaching for the
   production database. Then `systemctl reload postgresql-14`.

   Without this, "separate databases" is only a naming convention — the roles
   are what actually enforce it.

   The check, from each host:

   ```
   # from .104 — allowed
   psql -h 192.168.147.103 -U engg_uat -d engg_intranet_uat
   # from .104 — rejected
   psql -h 192.168.147.103 -U engg_uat -d engg_intranet
   ```

## One-time host setup — PROD (`192.168.147.105`, user `rhai`)

The PROD environment file already exists at `/home/rhai/hku-intranet/env.list`
(mode 0600), carrying `DB_NAME=engg_intranet` and `DB_USER=engg_prod` — the
PROD role, not the `postgres` superuser. The Jenkins agent needs
`ansible-playbook` and the SSH key — both are already there for the
`mcp-dr-pipeline` job (same agent container, same key). If the agent container
was recreated, re-run `scripts/install-jenkins-tools.sh`; it is idempotent.

PROD has no CI on it. The image is pulled from the registry on `.104` over the
network, and the PROD systemd user unit is the only thing the pipeline writes
on the host.

## Running it by hand

From a machine that can reach the hosts and has the key:

```bash
cd ansible

# UAT
ansible-playbook -i inventory.ini deploy.yml \
    -e intranet_target=intranet_uat \
    -e intranet_image=192.168.147.104:8082/hku-intranet:v1.1.28102612

# PROD
ansible-playbook -i inventory.ini deploy.yml \
    -e intranet_target=intranet_prod \
    -e intranet_image=192.168.147.104:8082/hku-intranet:v1.1.28102612
```

Add `--check --diff` first to see what would change.

## The inventory

UAT and PROD are two **different hosts**, each with its own deploy user.

| | UAT | PROD |
|---|---|---|
| host | `192.168.147.104` | `192.168.147.105` |
| user | `uat` | `rhai` |
| container | `hku-intranet-uat` | `hku-intranet` |
| unit | `hku-intranet-uat.service` | `hku-intranet.service` |
| port | 8097 | 8093 |
| env file | `hku-intranet-uat.env` | `env.list` |
| database | `engg_intranet_uat` | `engg_intranet` |
| db role | `engg_uat` | `engg_prod` |

To move UAT to another host, change its `ansible_host` and give it a deploy
user — nothing else changes. The database stays where it is; the env file
carries the host it must reach.

## What the role does

1. Checks the environment file is there. If it is not, the deployment **stops**
   with a message naming the path — the application would refuse to start
   without `SSO_COOKIE_SECRET`, and a silent failure is worse than a loud one.
2. Derives the site's env file from the source one (UAT only), rewriting `PORT`
   and `DB_NAME`. The secrets are copied, not retyped, and never printed.
3. Pulls the image from the registry — the same tag the pipeline pushed.
4. Installs the systemd user unit and **restarts** it. (Not `enable --now`:
   that is a no-op on an already-active unit, so the container would keep
   running the previous image.)
5. Waits for the port, then checks `/health` (liveness) and
   `/health/ready` (readiness — it names the database and reports
   whether it answers).
6. Asserts the running container is the promoted image, and that the site is
   talking to the database it is supposed to talk to.
7. Removes the superseded images. `rmi` refuses to remove an image a running
   container still holds — that is the safe outcome, not an error.

## Checking a site

```bash
curl -s http://192.168.147.104:8097/health              # UAT
curl -s http://192.168.147.104:8097/health/ready         # UAT  -> {"status":"ok","db":"ok","database":"engg_intranet_uat"}
curl -s http://192.168.147.105:8093/health/ready         # PROD -> {"status":"ok","db":"ok","database":"engg_intranet"}

ssh uat@192.168.147.104 'systemctl --user status hku-intranet-uat.service; podman images'
ssh rhai@192.168.147.105 'systemctl --user status hku-intranet.service; podman images'
```

The database name in `/health/ready` is the quickest proof that UAT and
PROD are different environments and not the same data wearing two hats.

`/health/ready` is **anonymous**: it answers 200 with the database name when
the database answers, and 503 with the same name plus the error when it does
not. The other database endpoint, `/api/db/connection`, is an **admin** page
— it names the same database but answers `401` to an anonymous probe, so it
belongs to the browser, not to a script.
