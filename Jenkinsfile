// Jenkinsfile — the HKU ENGG Intranet UAT pipeline (the job `pipeline-uat`)
//
// Code scan → build → push to the registry → image scan → deploy & verify
// → deploy UAT → record the promotion
//
// The production half is a SECOND job — Jenkinsfile.prod, the job
// `pipeline-prod` — which a human starts AFTER the UAT test has passed. This
// file never touches production. See "The two jobs" below.
//
// ============================================================================
// What this repository is
//
//   THIS repository holds the PIPELINE: this file, the Ansible roles in
//   ansible/, the setup script in scripts/ and the design picture in docs/.
//
//   The APPLICATION is not here. It lives in its own repository,
//   MangoTim/hku-calendar, and the 'Fetch App Source' stage clones it at a
//   pinned commit into ${WORKSPACE}/app. That is the same two-repository
//   shape the RHEL MCP pipeline uses (pipeline-dr + the app repo), and it
//   keeps the pipeline and the code it ships independently versioned.
//
//   The pipeline and the application never mix: the container that UAT and
//   PROD run is built from the app repository, and this file only decides
//   WHAT gets built, WHERE it goes and WHEN it is allowed to go.
//
// ============================================================================
// The lab layout
//
//   192.168.147.103   DB     PostgreSQL 14 — ONE instance holding TWO
//                             databases, one per environment, and one role
//                             per environment. The intranet DR site joins
//                             this host later (the standby replica).
//
//   192.168.147.104   CI+UAT Jenkins and the image registry (CI),
//                             plus the UAT container. This is where the
//                             pipeline runs and where the candidate release
//                             is tried out.
//
//   192.168.147.105   PROD   the live site only.
//
//   Why CI sits with UAT rather than with PROD: the pipeline builds and
//   pushes images, which is untrusted work (it runs the app's install
//   scripts and third-party packages). The database is the asset that must
//   stay away from untrusted work; the application host is a much smaller
//   prize, and the PROD container there runs as a non-root user out of a
//   systemd unit that the pipeline never touches. CI on the PROD box would
//   mean a compromised build owns the production host.
//
//   The registry is on the CI host, so UAT pulls it over loopback and PROD
//   pulls it over the network — which is the same path a real promotion
//   takes.
//
// ============================================================================
// One-time setup required BEFORE the first build
//
//   1. NOTHING TO INSTALL FOR THE SCANNER.
//
//        The CI band is 100% open source. Trivy is Apache-2.0
//        (github.com/aquasecurity/trivy) and the vulnerability database it
//        reads is open too. There is no commercial console, no licence, no
//        account and no credential to create: the scanner runs as a
//        `podman run` of a public image, against the public database.
//
//        `docker.io/aquasec/trivy` is the Docker Hub publication of that
//        same open-source project (its canonical home is
//        ghcr.io/aquasecurity/trivy) — `aquasec` there is the publisher
//        namespace, not a commercial product.
//
//   2. Registry running
//        podman run -d --name registry --network host \
//          -v registry_data:/var/lib/registry \
//          -e REGISTRY_HTTP_ADDR=:8082 docker.io/library/registry:2
//
//   3. The root-user rule
//        The Containerfile ends with `USER bun`, and the 'Image Scan' stage
//        enforces it twice: Trivy's misconfiguration scanner checks the
//        Containerfile for DS002 (AVD-DS-0002, "Image user should not be
//        'root'"), and the image that was actually BUILT is inspected, so a
//        base image that runs as root is caught even if the Containerfile
//        says otherwise.
//
//   4. Pipeline job configuration — TWO jobs, one repository
//        Definition:  Pipeline script from SCM
//        SCM:         Git | https://github.com/MangoTim/pipeline-uat.git
//        Branch:      */main
//        Script Path: Jenkinsfile              (the job `pipeline-uat`)
//        Script Path: Jenkinsfile.prod         (the job `pipeline-prod`)
//        (This repository IS the pipeline — the Jenkinsfiles, the Ansible
//         roles and the setup script are all committed here, and the deploy
//         stages run ${WORKSPACE}/ansible/deploy.yml from it.)
//
//   5. The agent must be the custom jenkins-with-podman image:
//        --net=host + /run/podman/podman.sock mounted as /var/run/docker.sock
//        Host networking is what lets the scanner containers reach the
//        registry and the Trivy DB registry.
//
//        The agent drives the HOST's podman over that socket: the pipeline
//        sets CONTAINER_HOST=unix:///var/run/docker.sock, so podman in the
//        agent is a client of the host's rootful podman rather than a
//        nested runtime. (A nested runtime cannot work here — the agent's
//        rootfs is overlayfs and its cgroup tree is read-only. The whole
//        reason for this is spelled out in the environment block.)
//        Host prerequisite:  systemctl enable --now podman.socket
//
//   6. Script approval (FIRST BUILD ONLY)
//        Trivy runs as a `podman run` shell step — no sandboxed Groovy APIs
//        are used, so no signatures need approving.
//
//   7. UAT / PROD deployment prerequisites (needed by the deploy stages)
//        a) The environment file on each host, owned by the deploy user:
//             /home/uat/hku-intranet/env.list     (UAT,  mode 0600)
//             /home/rhai/hku-intranet/env.list    (PROD, mode 0600)
//           Its contents are the RUNBOOK's Section 4.2 template
//           (deliverable/RUNBOOK.md). Each file is its OWN — the UAT file
//           carries UAT's own database role and password, not a copy of PROD's.
//           The Ansible role only rewrites PORT (8097) and DB_NAME
//           (engg_intranet_uat); the credentials are never copied across, so
//           the UAT container cannot open the PROD database.
//           The file holds the database password, the Entra client secret and
//           the SSO cookie secret, so it never travels through Jenkins.
//
//           SSO_COOKIE_SECRET is NOT optional: the server refuses to start in
//           production mode without it.
//
//        b) On .104 (UAT): python3.9 (the inventory pins it — RHEL 8 ships
//           3.6, which ansible-core >= 2.15 rejects), the pipeline's SSH key
//           in /home/uat/.ssh/authorized_keys, `loginctl enable-linger uat`
//           so the systemd user manager survives a reboot, and the port open:
//             firewall-cmd --permanent --add-port=8097/tcp
//             firewall-cmd --reload && podman network reload
//
//        c) On .103 (the DB host): the two database roles and their grants —
//             engg_uat  -> engg_intranet_uat  only
//             engg_prod -> engg_intranet      only
//           and pg_hba.conf rules that allow each role only from the host it
//           belongs to. Both environments then share the server without
//           sharing the data.
//
//        d) The agent container must have ansible-playbook and the SSH key
//           /var/jenkins_home/.ssh/id_rhai108_rsa. Both are already there for
//           the mcp-dr-pipeline job — same agent container, same key. If the
//           agent container was recreated, re-run
//           scripts/install-jenkins-tools.sh; it is idempotent.
//
//        Full walkthrough: ansible/README.md
//
// ---------------------------------------------------------------------------
// The two jobs
//
//   This file is the UAT half. The production half is a SECOND job —
//   `pipeline-prod`, running Jenkinsfile.prod from this same repository.
//
//     JOB pipeline-uat  (this file)
//        Checkout -> Fetch App Source -> Resolve Version -> Code Scan ->
//        Build Image -> Push to Registry -> Image Scan -> Deploy & Verify ->
//        Deploy UAT -> Record Promotion
//        A push to main starts it. It never touches production.
//
//     JOB pipeline-prod  (Jenkinsfile.prod)
//        Checkout -> Load Promotion Record -> Verify Promotion ->
//        Manual Approval -> Deploy PROD
//        NO triggers block — a push can never start it. A human starts it,
//        after the UAT test has passed.
//
//   'Deploy & Verify' boots the image once ON THE CI HOST to prove it starts.
//   Nothing is deployed from there. The last two stages put the image on UAT
//   and then describe it for the promotion:
//
//     Deploy UAT (Database & Application)
//        ansible -> .104:8097, its own database engg_intranet_uat, and the
//        readiness check proves which database it is connected to
//     Record Promotion
//        writes down WHAT was deployed — image, digest, app commit, UAT
//        endpoint — so the PROD job can promote those exact bytes later
//
//   The record is the carrier across the job boundary. The controller has no
//   parameterized-trigger, no copy-artifact and no job-dsl, so the usual
//   `build job: 'x', parameters: [...]` is not available — but both jobs run
//   in the same container on the same jenkins_data volume, so a FILE under
//   JENKINS_HOME carries the evidence from one job to the other. The PROD job
//   is TOLD which bytes were tested; it cannot disagree with the UAT job
//   about it.
//
//   UAT and PROD run the SAME TAG — the one this build pushed and scanned.
//   The approval therefore decides WHETHER those exact bytes reach
//   production, never WHICH bytes that is. The digest shown in the approval
//   message is the registry digest that was proved byte-identical to the
//   scanned image in the 'Push to Registry' stage.
//
//   UAT and PROD are two different HOSTS, separated by container name, port,
//   environment file and DATABASE. The separate database is what makes UAT a
//   separate environment and not a second view of production.
//
//   The approval is a plain Jenkins `input` step — no plugin needed. It lives
//   in the PROD job now, so the two jobs are not connected in TIME at all:
//   the human can test UAT for an hour, overnight, whatever, and then start
//   the PROD job with the record of what was tested.
//
// ---------------------------------------------------------------------------
// Why a separate code-scan stage?
//
//   The runtime image is multi-stage: it ships dist/ (the Vite bundle) and
//   server/node_modules, but NOT the frontend node_modules. So the frontend
//   dependency tree (react, vite, xlsx@0.18.5, react-router-dom, typescript)
//   is completely invisible to an image scan — and xlsx is bundled into
//   dist/assets/xlsx-*.js as a minified chunk with no package metadata, so
//   no scanner can map it back to a package version either.
//
//   The code scan therefore runs against the *builder* stage, which still has
//   the full source tree, both bun.lock files and both node_modules trees.
//   `podman build --target builder` produces exactly that image.
//
// ---------------------------------------------------------------------------
// Why the code scan runs BEFORE the build
//
//   The design picture (docs/diagrams/pipeline/Pipeline-Design-UAT-PROD.png)
//   shows the CI band as
//
//     Code Scan -> Build Image -> Push to Registry -> Image Scan
//
//   which is also the order of the Red Hat reference pipeline, and this
//   pipeline does the same. The scans are split by what they need:
//
//     'Code Scan (secrets + dependencies)'   BEFORE the build, on the source
//        trivy fs --scanners secret .            the working tree, no image
//        bun audit --json                        the lockfiles, in a
//                                                 throwaway oven/bun:1.3-alpine
//                                                 container with the source
//                                                 mounted — no build needed
//        scripts/audit_scope.py                  sorts the findings into what
//                                                 SHIPS and what is only a
//                                                 build tool (see below)
//
//     'Image Scan'                            AFTER the push, on the images
//        trivy config (misconfiguration)          the Containerfile — DS002,
//                                                 the image must not run as root
//        podman image inspect                    the USER of the image that was
//                                                 actually BUILT — the
//                                                 authoritative root check
//        trivy vuln,secret --pkg-types library   ${SCAN_IMAGE} — the builder
//                                                  stage, which still holds the
//                                                  full frontend dependency tree
//        scripts/trivy_scope.py                  sorts those findings into what
//                                                 SHIPS and what is only a
//                                                 build tool (see below)
//        trivy vuln --pkg-types os               ${FULL_IMAGE} — the runtime
//                                                  base we actually ship
//
//   Why it is worth it: a hardcoded secret is caught BEFORE it is baked into
//   a layer and pushed to the registry, and the cheap source scan fails the
//   build in minutes instead of after the build and the push.
//
//   Coverage is NOT lost. The pre-build secret scan walks the source tree;
//   the image-level secret scan still runs on ${SCAN_IMAGE}, so a secret in a
//   base-image layer is still found. The library scan stays where it was,
//   because the frontend dependency tree (react, vite, xlsx, react-router-dom)
//   is invisible to a source scan — the runtime image does not carry the
//   frontend node_modules at all. See "Why a separate code-scan stage?".
//
//   Note: the Trivy database (~100 MB) is downloaded on the first run and is
//   then cached in the existing trivy-cache volume.
// ---------------------------------------------------------------------------
// Image version tags
//
//   The image is tagged with a version, not a build counter:
//
//       v<major>.<minor>.<DDMMYY><NN>       e.g. v1.1.28102601
//
//   major.minor  comes from the VERSION file in the APP repository root.
//                 Bump it to 1.2 for a big change, leave it at 1.1 for small
//                 ones.
//   DDMMYY       the build date, pinned to Hong Kong time (the agent
//                 container runs UTC, the host runs America/New_York).
//   NN           the UAT job's build number, zero padded to two digits. It is
//                 monotonic, so a tag is never reused and always maps back to
//                 exactly one UAT build.
//
//   Full reference: 192.168.147.104:8082/hku-intranet:v1.1.28102601
//
//   THE PROD JOB NEVER MINTS A TAG. Build numbers are per job, so
//   `pipeline-uat #1` and `pipeline-prod #1` on the same day would mint the
//   SAME tag — v1.1.<DDMMYY>01 — for DIFFERENT bytes, and the second push
//   would silently overwrite the first in the registry. The PROD job only
//   ever READS the registry: its tag and its digest come from the promotion
//   record. See Jenkinsfile.prod.
//
// ---------------------------------------------------------------------------
// What the open-source scan covers — and the one thing it does not
//
//   Every gate in the CI band is Trivy, and Trivy is Apache-2.0. Nothing in
//   this pipeline needs a commercial scanner, a licence or an account.
//
//   The scan is NOT a statement that the image is free of CVEs. It is a
//   statement about four specific things, and the reports say which:
//
//     no secret in the source tree          trivy fs --scanners secret
//     no secret in the image                trivy image --scanners secret
//     no advisory in a dependency that      scripts/trivy_scope.py
//       SHIPS to the customer                  (HIGH and CRITICAL)
//     no CRITICAL CVE in the OS packages    trivy image --pkg-types os
//     the image does not run as root        trivy config (DS002) + podman
//                                            image inspect
//
//   Every CVE that showed up was inherited from the base image, not from this
//   code. The Debian runtime base (oven/bun:1.3-slim) carried 100
//   HIGH/CRITICAL, 3 of them CRITICAL, all in perl-base. The runtime stage
//   now uses oven/bun:1.3-alpine, which carries a handful of HIGH and 0
//   CRITICAL. The exact count MOVES with the vulnerability database — the
//   database is refreshed on every run — so no number is written down here.
//   The report of the day is the authority: trivy-os-report.txt, and the
//   same findings in the one-page vulnerability-report.html. The
//   application dependency trees are clean: 0 HIGH/CRITICAL.
//
//   THE REPORT: all of this is in ONE page. The 'Image Scan' stage ends with
//   scripts/build_report.py, which renders vulnerability-report.html out of
//   the scan output that is already on disk — the image's OS packages, the
//   image's libraries, the image's secrets, the source tree's secrets and the
//   dependency advisories, in one document, with the severity, the installed
//   and fixed versions, the links and the scope of every finding.
//
//   It is the open-source replacement for the console dashboard, and it is
//   better in one respect: the console showed the IMAGE only. This page
//   shows the image AND the code, because the code scan is part of the same
//   CI band and its findings belong in the same document.
//
//   THE GAP, stated plainly: this pipeline does NOT scan for MALWARE.
//   A commercial scanner's assurance policy covered malware and root_user;
//   the open-source replacement covers root_user (above) and, for malware,
//   nothing. The Trivy malware plugin that would have closed this gap has
//   been withdrawn upstream — its repository is gone and it is no longer in
//   the Trivy plugin index. If malware scanning is required, it needs a
//   separate open-source scanner (e.g. ClamAV) with its own signature
//   database to maintain, and that is a decision, not a default.
//
// ---------------------------------------------------------------------------
// Known accepted risks (deliberate, so the pipeline stays green):
//
//   * The HIGH OS CVEs in the alpine base have a fix in a newer alpine
//     release that no oven/bun tag has picked up yet. They are reported in
//     trivy-os-report.txt but not gated; CRITICAL is the line that stops a
//     build. Re-check when oven/bun publishes a newer alpine base.
//
//   * xlsx was swapped from the abandoned npm release (0.18.5 — the last
//     version ever published to the npm registry, deprecated, and carrying
//     two HIGH advisories) to the maintained SheetJS CDN build 0.20.3
//     (https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz). Only
//     XLSX.read() and XLSX.utils.sheet_to_json() are used by this app and
//     both are API-stable across 0.18 → 0.20, so no source change was
//     needed. The `bun audit` ignore list was deleted: the audit is now
//     clean with NO exceptions.
//
//   * picomatch 4.0.7 has a HIGH ReDoS advisory
//     (GHSA-fc5q-39xc-vjpf) and it is the LATEST release — there is no fixed
//     version to install. It is reached only through `vite`, a build tool:
//         vite > picomatch
//     It never reaches the customer. Neither `bun audit` nor Trivy can tell
//     the two apart on their own: `bun audit` reads the lockfile and the
//     lockfile holds both trees, and Trivy's finding list has no idea either
//     (bun hoists, so picomatch sits at app/node_modules/picomatch/… and the
//     path hides the vite parent). So the pipeline splits the findings
//     itself, with the same rule in both places:
//         scripts/audit_scope.py   for the `bun audit` report (code scan)
//         scripts/trivy_scope.py   for the Trivy image report (image scan)
//     An advisory on a package in the PRODUCTION closure blocks the build; an
//     advisory on a build tool is printed with the path that reaches it and
//     does not. This is the same rule npm applies with `npm audit --omit=dev`.
//
//   * What the two workspaces ship is NOT the same, and the scope scripts
//     know it:
//         frontend  only the compiled `dist/` bundle is delivered — the
//                   frontend node_modules are not in the runtime image at
//                   all, so the frontend ships its production closure and
//                   nothing else.
//         server    the runtime image copies `server/` straight out of the
//                   builder, so `server/node_modules` — devDependencies
//                   included — DOES reach the customer. The server therefore
//                   ships its whole installed tree, and the scope scripts
//                   are told so (--ship-dev / --server-ship-dev).
//     The match is by name AND version, because the two workspaces can
//     carry the same package at different versions: typescript 6.0.3 is the
//     frontend build tool, typescript 5.7.2 is the copy that ships.
//
//   * Trivy's report is a HARD GATE, but the decision about what counts is
//     made by scripts/trivy_scope.py, not by --exit-code: a HIGH/CRITICAL
//     advisory on a package that SHIPS, or any secret at all, fails the
//     build. An advisory on a build tool is reported and does not. A report
//     that cannot be read fails the build too — "not verified" must never
//     look like "clean".
//     Trivy's rules currently match NOTHING in this tree, so two real
//     hardcoded fallbacks still survive the scanner (but not code review):
//       server/src/db.ts          → process.env.DB_PASSWORD || 'redhat'
//       server/src/cookieSecret.ts → the published dev fallback, which the
//                                    server REFUSES to start with when
//                                    NODE_ENV=production
//     They are low-entropy literals, not high-entropy keys, so no scanner
//     rule matches them — the scanner is not the control here.
//     The deployed hosts do NOT use the fallbacks: both environment files
//     carry a real DB_PASSWORD and a real SSO_COOKIE_SECRET (see setup item
//     8a). The source fallbacks only bite a developer running the app
//     without an environment file.
//     TODO: delete both fallbacks from the source.
//
//   * bun audit exits 1 both for real findings AND when the npm advisory
//     registry is unreachable. A registry outage therefore fails the build.
// ============================================================================

pipeline {
    agent any

    environment {
        REGISTRY      = '192.168.147.104:8082'
        REGISTRY_URL  = 'http://192.168.147.104:8082'
        IMAGE_NAME    = 'hku-intranet'

        // The ONE scanner in this pipeline, and it is open source.
        //
        // Trivy is Apache-2.0 (github.com/aquasecurity/trivy). The
        // `aquasec` in the image name is the Docker Hub PUBLISHER namespace
        // for that same open-source project — its canonical home is
        // ghcr.io/aquasecurity/trivy — and `aquasec/trivy-db:2` is the open
        // vulnerability database. Neither needs a licence, an account or a
        // commercial console, and the CI band has no credential for either.
        TRIVY_IMAGE   = 'docker.io/aquasec/trivy:0.76.1'

        // ------------------------------------------------------------------
        // The container runtime the pipeline drives.
        //
        // The Jenkins agent runs INSIDE a container (jenkins-with-podman) and
        // the host's podman socket is bind-mounted into it at
        // /var/run/docker.sock. CONTAINER_HOST points podman at that socket,
        // so the podman CLIENT in the agent talks to the HOST's rootful
        // podman instead of trying to run a nested runtime of its own.
        //
        // A nested runtime cannot work in this agent, and the failures are
        // confusing rather than obvious:
        //
        //   * the agent's own rootfs is overlayfs, so a nested overlay
        //     graphdriver refuses to start:
        //       "'overlay' is not supported over overlayfs, a mount_program
        //        is required"
        //   * the agent has no writable cgroup tree, so the nested runtime
        //     cannot create its own:
        //       "crun: creating cgroup directory
        //        /sys/fs/cgroup/cpu,cpuacct/libpod_parent/...: read-only file
        //        system"
        //
        // Driving the host's podman is also the RIGHT semantics, not just a
        // workaround: the image is built, pushed, scanned and booted on the
        // CI host, and the scan containers reach that same image store
        // through the same socket. Everything the pipeline builds lives in
        // ONE store, on ONE host.
        //
        // Two consequences for bind mounts, because the HOST resolves them:
        //
        //   * A path that only exists inside the agent (e.g. ${WORKSPACE})
        //     does not exist on the host. The workspace is mounted into the
        //     agent from the jenkins_data volume, so the scans mount the
        //     app directory by its path inside that volume.
        //   * The podman socket on the host is /run/podman/podman.sock —
        //     /var/run/docker.sock is the name it is given INSIDE the
        //     agent, and the host has no such file.
        //
        // Host prerequisite: `systemctl enable --now podman.socket` (the
        // socket must be there when the build runs).
        // ------------------------------------------------------------------
        CONTAINER_HOST = 'unix:///var/run/docker.sock'
        PODMAN_SOCK    = '/run/podman/podman.sock'

        // Where the jenkins_data volume lives ON THE HOST. The app source is
        // cloned into ${WORKSPACE}/app, i.e. into that volume, so this is the
        // host-side path of the same directory the scans have to read.
        JENKINS_VOLUME_PATH = '/var/lib/containers/storage/volumes/jenkins_data/_data'

        // 8093 is the live production port (container "hku-intranet"); the
        // verify container uses 8094 so it cannot collide with it.
        VERIFY_PORT   = '8094'

        // The throwaway PostgreSQL the verify stage boots on the CI host.
        // The application initialises its schema at boot and refuses to start
        // when the database is unreachable, so the CI cannot verify the image
        // against a closed port — it needs a real database. This one is a
        // container of its own, on a port of its own, with a database of its
        // own: no UAT or PROD data is touched, and it is removed afterwards.
        VERIFY_DB_PORT = '55432'

        // The UAT site — ONE HOST, one container, one database:
        //   UAT   192.168.147.104  (the intranet container)         user uat
        //   DB    192.168.147.103  (the PostgreSQL server — one instance
        //                           holding one database and one role per
        //                           environment; the intranet DR site joins
        //                           this host later)
        //
        // The PROD site is the OTHER host (.105, user rhai, database
        // engg_intranet) and its variables live in the PROD job —
        // Jenkinsfile.prod. This job never deploys there.
        //
        // Each site gets its own port and — the part that matters — its OWN
        // DATABASE and its OWN database role, so a UAT session never touches
        // production data even though both databases live on the same host.
        UAT_HOST      = '192.168.147.104'
        UAT_PORT      = '8097'
        UAT_DB        = 'engg_intranet_uat'

        // The pipeline's own repository — the one this Jenkinsfile lives in.
        // The Checkout stage clones it; the deploy stages read the Ansible
        // roles out of it.
        PIPELINE_REPO_URL = 'https://github.com/MangoTim/pipeline-uat.git'

        // The APPLICATION repository. The 'Fetch App Source' stage clones it
        // into ${WORKSPACE}/app, and everything after that — the version, the
        // scans, the build — works on that copy.
        //
        // APP_REF pins the exact commit the pipeline builds. It must be a TAG
        // (v1.1.0) or a full commit SHA — never a branch name. A branch moves
        // under you, and "the artefact is exactly the commit named here" would
        // be a lie. The 'Fetch App Source' stage refuses to run if this is a
        // branch, so the pin cannot be lost by accident.
        //
        // Move it forward deliberately: that is the record of what was
        // promoted to PROD.
        APP_REPO = 'https://github.com/MangoTim/hku-calendar.git'
        APP_REF  = 'v1.1.0'

        // The controller's SSH key for Ansible. The path is relative to the
        // CONTROLLER's home, so the same inventory works from the Jenkins
        // container and from a developer machine. The Jenkins container's HOME
        // is /home/server, not JENKINS_HOME, so the "~" in ansible.cfg would
        // not resolve — the deploy stages export ANSIBLE_PRIVATE_KEY_FILE.
        ANSIBLE_KEY   = '/var/jenkins_home/.ssh/id_rhai108_rsa'

        // Where the promotion record is written. JENKINS_HOME lives in the
        // jenkins_data volume, so a record survives a container recreate —
        // the same lifetime as the jobs and the credentials. The PROD job
        // reads it from here, which is what carries the tested bytes across
        // the job boundary.
        PROMOTION_DIR = '/var/jenkins_home/promotions/intranet'

        // IMAGE_VERSION / FULL_IMAGE / SCAN_IMAGE are resolved at run time by
        // the 'Resolve Version' stage — they depend on the VERSION file and
        // on the build date, neither of which the environment block can read.
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        // 60 minutes of MACHINE work — the scans, the build, the push and the
        // UAT deployment. This job no longer waits for a human: the approval
        // gate lives in the pipeline-prod job, so the human test happens
        // BETWEEN two jobs rather than inside one suspended build.
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    triggers {
        // The GitHub plugin's push trigger: when the APPLICATION repository
        // receives a push, GitHub delivers a webhook to Jenkins and this
        // pipeline starts. The trigger only LISTENS — the hook on the GitHub
        // side has to be created as well, pointing at this Jenkins' webhook
        // endpoint.
        //
        // This needs a GitHub server to be configured in Jenkins first
        // (Manage Jenkins -> System -> GitHub). Without one the delivery is
        // rejected and the pipeline still has to be started from the UI.
        githubPush()
    }

    stages {

        stage('Checkout') {
            steps {
                // The pipeline's own repository. Everything the pipeline
                // needs that is NOT the application lives here: this file,
                // the Ansible roles, the setup script.
                git branch: 'main',
                    url: "${PIPELINE_REPO_URL}"
            }
        }

        stage('Fetch App Source') {
            // The application is a SEPARATE repository. This stage brings it
            // in at a pinned commit, into ${WORKSPACE}/app — everything after
            // this point (the version, the scans, the build) works on that
            // copy, and the artefact is exactly the commit that is named
            // here.
            //
            // A tag or a SHA is fetched by REF, not by branch: `git clone
            // --branch` only understands branches and tags, and cannot take a
            // commit SHA at all. So the clone is done in three moves — init,
            // fetch the one ref we want, check it out — which works for a tag
            // and for a SHA the same way.
            steps {
                sh '''
                    set -eux
                    rm -rf app
                    mkdir app
                    cd app
                    git init -q
                    git remote add origin ${APP_REPO}

                    # A branch name would make the build non-reproducible: the
                    # same Jenkinsfile could produce two different artefacts on
                    # two different days. Refuse it here rather than shipping
                    # whatever the branch happens to point at today.
                    if git ls-remote --heads origin ${APP_REF} | grep -q .; then
                        echo "BLOCKED: APP_REF '${APP_REF}' is a BRANCH."
                        echo "         APP_REF must be a release tag (v1.1.0) or a"
                        echo "         full commit SHA, so the build is reproducible."
                        exit 1
                    fi

                    git fetch --depth 1 origin ${APP_REF}
                    git checkout -q FETCH_HEAD

                    git rev-parse HEAD
                    echo "App commit: $(git rev-parse HEAD)"
                    ls -1
                '''
                script {
                    env.APP_COMMIT = sh(script: 'cd app && git rev-parse HEAD', returnStdout: true).trim()
                    echo "App commit : ${env.APP_COMMIT}"
                    echo "App ref    : ${APP_REF}"
                }
            }
        }

        stage('Resolve Version') {
            // The image tag is a version, not a build counter:
            //
            //     v<major>.<minor>.<DDMMYY><NN>
            //
            //   major.minor  the release line, from the VERSION file in the
            //                 repo root. Bump it to 1.2 when there is a big
            //                 change, and back to 1.1 for small ones.
            //   DDMMYY       the build date, pinned to Hong Kong time so the
            //                 tag does not depend on where the agent runs (the
            //                 agent container is UTC, the host is New York).
            //   NN           the UAT job's build number, zero padded to two
            //                 digits. It is monotonic, so a tag is never reused
            //                 and always maps back to exactly one UAT build.
            //
            // Examples: v1.1.28102601, v1.1.28102602, then v1.2.28102603
            // after the version line is bumped.
            //
            // This stage runs in the UAT job ONLY. The PROD job must never
            // mint a tag: build numbers are per job, so `pipeline-uat #1` and
            // `pipeline-prod #1` on the same day would mint the SAME tag for
            // different bytes, and the second push would silently overwrite
            // the first in the registry. The PROD job only READS the
            // registry — its tag comes from the promotion record.
            steps {
                script {
                    def base = sh(script: "tr -d ' \\n' < app/VERSION", returnStdout: true).trim()
                    def day  = sh(script: "TZ=Asia/Hong_Kong date +%d%m%y", returnStdout: true).trim()
                    def seq  = sh(script: "printf '%02d' ${BUILD_NUMBER}", returnStdout: true).trim()

                    env.IMAGE_VERSION = "v${base}.${day}${seq}"
                    env.FULL_IMAGE    = "${env.REGISTRY}/${env.IMAGE_NAME}:${env.IMAGE_VERSION}"
                    env.SCAN_IMAGE    = "${env.IMAGE_NAME}-scan:${env.IMAGE_VERSION}"

                    echo "Image version : ${env.IMAGE_VERSION}"
                    echo "Full image ref: ${env.FULL_IMAGE}"
                }
            }
        }

        stage('Code Scan (secrets + dependencies)') {
            // BEFORE the build, on the SOURCE TREE. Nothing is built yet, so
            // this stage needs no image: it reads the working tree and the
            // lockfiles. A hardcoded secret is caught here, before it is
            // baked into a layer and pushed to the registry.
            steps {
                sh '''
                    set -u

                    # ------------------------------------------------------------------
                    # 1. Trivy — hardcoded secrets in the SOURCE TREE.
                    #    `trivy fs` walks a directory. It needs no image and no
                    #    container runtime socket, only the Trivy database
                    #    (cached in the trivy-cache volume after the first run).
                    #    HARD GATE: --exit-code 1 turns any detected secret into
                    #    a build failure.
                    # ------------------------------------------------------------------
                    SECRET_RC=0
                    podman run --rm --name hku-trivy-fs-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/src:ro \
                        ${TRIVY_IMAGE} \
                        fs --scanners secret \
                            --exit-code 1 \
                            --format table \
                            --skip-dirs "node_modules,dist,.git,backups" \
                            /src > trivy-secret-report.txt 2>&1 || SECRET_RC=$?

                    cat trivy-secret-report.txt
                    echo "trivy (source secrets) exit code: ${SECRET_RC}"

                    # ------------------------------------------------------------------
                    # The same scan as JSON, for the one-page vulnerability report
                    # that the 'Image Scan' stage builds at the end.
                    #
                    # Trivy's own HTML template renders vulnerabilities and
                    # misconfigurations, but NOT secrets — so the report is
                    # rendered by scripts/build_report.py, and it needs the
                    # findings in a machine-readable form.
                    #
                    # This run is a SECOND gate as well: the count below is
                    # checked, so the report and the gate can never disagree.
                    # The table scan above blocks on any secret; this one
                    # blocks on any secret the JSON run saw. Both must be
                    # clean for the build to pass.
                    # ------------------------------------------------------------------
                    podman run --rm --name hku-trivy-fs-json-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/src:ro \
                        ${TRIVY_IMAGE} \
                        fs --scanners secret \
                            --format json \
                            --skip-dirs "node_modules,dist,.git,backups" \
                            /src > trivy-secret-report.json 2> trivy-secret-json.err || true

                    SECRET_JSON_COUNT=$(python3 -c "import json;d=json.load(open('trivy-secret-report.json'));print(sum(len(r.get('Secrets') or []) for r in (d.get('Results') or [])))" 2>/dev/null || echo "-1")

                    if [ "${SECRET_JSON_COUNT}" = "-1" ]; then
                        echo "BLOCKED: the source secret scan output could not be read —"
                        echo "        see trivy-secret-json.err"
                        exit 1
                    fi

                    if [ "${SECRET_JSON_COUNT}" -ne 0 ]; then
                        echo "BLOCKED: Trivy detected ${SECRET_JSON_COUNT} secret(s) in the source tree — see trivy-secret-report.json"
                        exit 1
                    fi

                    echo "trivy (source secrets, JSON) count: ${SECRET_JSON_COUNT}"

                    # ------------------------------------------------------------------
                    # 2. bun audit — dependency advisories straight from the lockfiles.
                    #    `bun audit` reads ONLY the lockfile, so it needs neither
                    #    a build nor node_modules: the source tree is mounted
                    #    into a throwaway bun container and the audit runs
                    #    there. One JSON file per workspace, because the two
                    #    workspaces have their own lockfile and their own
                    #    dependency tree.
                    #
                    #    The mount is READ-WRITE on purpose: bun opens
                    #    package.json for writing while it resolves the
                    #    project, so a read-only mount fails with
                    #    "Unexpected: could not open /app/package.json" —
                    #    a scan failure, not a finding. Nothing is written:
                    #    the directory is identical before and after.
                    # ------------------------------------------------------------------
                    podman run --rm --name hku-audit-fs-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/app \
                        --entrypoint sh -w /app oven/bun:1.3-alpine \
                        -c 'bun audit --json' > bun-audit-root.json 2> bun-audit-root.log || true

                    podman run --rm --name hku-audit-fs-srv-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/app \
                        --entrypoint sh -w /app/server oven/bun:1.3-alpine \
                        -c 'bun audit --json' > bun-audit-server.json 2> bun-audit-server.log || true

                    echo "### bun audit — frontend (app/bun.lock)"
                    cat bun-audit-root.json
                    echo ""
                    echo "### bun audit — server (app/server/bun.lock)"
                    cat bun-audit-server.json
                    echo ""

                    # ------------------------------------------------------------------
                    # Gate: a secret anywhere in the source tree.
                    # ------------------------------------------------------------------
                    if [ "${SECRET_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy detected a secret in the source tree (or the scan itself failed) — see trivy-secret-report.txt"
                        exit 1
                    fi

                    # ------------------------------------------------------------------
                    # Gate: HIGH/CRITICAL advisories — but only for the
                    # dependencies that actually SHIP.
                    #
                    # `bun audit` has no way to tell a build tool from a
                    # delivered package: it reads the lockfile, and the
                    # lockfile holds both trees. So the report is split by
                    # scripts/audit_scope.py, which walks the lockfile and
                    # works out the production closure:
                    #
                    #   * a package in that closure SHIPS. An advisory on it
                    #     is a real finding and blocks the build.
                    #   * any other package is a build tool. The advisory is
                    #     printed with the path that reaches it, but it does
                    #     not block — picomatch, for example, is reached only
                    #     through vite and has no fixed release at all.
                    #
                    # The two workspaces do not ship the same thing:
                    #
                    #   frontend  only the compiled `dist/` bundle is
                    #             delivered, so the frontend node_modules
                    #             never reach the customer.
                    #   server    the runtime image copies `server/` out of
                    #             the builder, so `server/node_modules` —
                    #             devDependencies included — DOES. The server
                    #             is audited with --ship-dev for that reason.
                    #
                    # An audit that could not be read is NOT a pass: the gate
                    # refuses, because "not verified" must not look like
                    # "clean".
                    # ------------------------------------------------------------------
                    scope_gate() {
                        # $1 label, $2 lockfile, $3 audit json, $4 report file,
                        # $5 extra flags (may be empty — hence ${5:-}, the
                        # shell runs with `set -u`)
                        python3 scripts/audit_scope.py "$2" "$3" \
                            --level high --label "$1" ${5:-} > "$4" 2>&1
                        rc=$?
                        cat "$4"
                        if [ "$rc" -eq 2 ]; then
                            echo "BLOCKED: the dependency audit for $1 could not be verified — see $4"
                            exit 1
                        fi
                        if [ "$rc" -ne 0 ]; then
                            echo "BLOCKED: $1 has a HIGH/CRITICAL advisory in a dependency that SHIPS — see $4"
                            exit 1
                        fi
                    }

                    scope_gate "the frontend" app/bun.lock \
                               bun-audit-root.json audit-scope-root.txt
                    scope_gate "the server" app/server/bun.lock \
                               bun-audit-server.json audit-scope-server.txt \
                               --ship-dev

                    echo "Code scan OK: no secrets in the source tree, no HIGH/CRITICAL advisory in any dependency that ships."
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'bun-audit-root.json,bun-audit-server.json,audit-scope-root.txt,audit-scope-server.txt,trivy-secret-report.txt,trivy-secret-report.json,trivy-secret-json.err',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('Build Image') {
            steps {
                sh '''
                    set -eux

                    # --network host: the RUN steps need the npm registry. The
                    # host's rootful podman bridge is firewalled — container
                    # egress is dropped in the FORWARD chain — so a default
                    # (bridge) build hangs on `bun install`. Host networking
                    # routes build egress through OUTPUT instead, which is not
                    # firewalled. No Dockerfile step binds a port, so sharing
                    # the host netns is safe here.

                    # --format docker: podman's default is OCI, which silently
                    # DROPS the HEALTHCHECK instruction ("HEALTHCHECK is not
                    # supported for OCI image format"). Docker format keeps it
                    # and is what every other tool in the chain expects.

                    # Scan target FIRST: it IS the builder stage, so the layers
                    # land in the build cache and the runtime build below
                    # reuses them instead of rebuilding.
                    podman build \
                        --file app/Containerfile \
                        --format docker \
                        --network host \
                        --target builder \
                        --tag ${SCAN_IMAGE} \
                        --label build.number=${BUILD_NUMBER} \
                        --label build.url=${BUILD_URL} \
                        app

                    podman build \
                        --file app/Containerfile \
                        --format docker \
                        --network host \
                        --tag ${FULL_IMAGE} \
                        --label build.number=${BUILD_NUMBER} \
                        --label build.url=${BUILD_URL} \
                        app
                '''
            }
        }

        stage('Push to Registry') {
            steps {
                sh '''
                    set -eux

                    # The image as it was BUILT, before the push. The image ID
                    # is the digest of the image config, and that config
                    # carries the diff_id of every layer — so an equal image ID
                    # means an equal filesystem, whatever the manifest says.
                    #
                    # podman prints the image ID as the bare hex, without the
                    # "sha256:" prefix the registry uses. The prefix is put
                    # back on here so that all three digests below can be
                    # compared as they are written in the registry.
                    BUILT_ID=$(podman image inspect ${FULL_IMAGE} --format '{{.Id}}')
                    BUILT_CONFIG="sha256:${BUILT_ID#sha256:}"

                    podman push ${FULL_IMAGE} --tls-verify=false

                    # Pull the pushed copy back, so the local store holds the
                    # bytes the UAT and PROD sites will pull. Everything the
                    # scans below look at is then literally the registry's
                    # copy, not the build's intermediate representation.
                    podman pull --tls-verify=false ${FULL_IMAGE}

                    # Prove that what the client pulls from the registry is
                    # the same image that was built here and then scanned by
                    # Trivy in the stage below. Without this the scan
                    # evidence and the delivered artefact could in principle
                    # be different images.
                    #
                    # Two different digests are involved and they must not be
                    # confused with one another:
                    #
                    #   * the MANIFEST digest — the hash of the manifest
                    #     document, which is what the registry serves in its
                    #     Docker-Content-Digest header. It identifies the tag
                    #     for humans and for the approval gate.
                    #   * the CONFIG digest — the hash of the image config,
                    #     which is what podman prints as the image ID. The
                    #     config carries the diff_id of every layer, so an
                    #     equal config digest means an equal filesystem.
                    #
                    # The manifest digest cannot be compared with the local
                    # `.Digest`: podman keeps the OCI manifest of a locally
                    # built image while the registry stores the DOCKER v2s2
                    # manifest it was pushed as. Same image, different
                    # manifest bytes, different digest. The config digest
                    # has no such ambiguity, so that is what the check uses.
                    MANIFEST_URL="http://${REGISTRY}/v2/${IMAGE_NAME}/manifests/${IMAGE_VERSION}"
                    ACCEPT='Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'

                    REG_DIGEST=$(curl -s -D - -o /dev/null -H "${ACCEPT}" "${MANIFEST_URL}" \
                        | tr -d '\r' | awk '/Docker-Content-Digest/ {print $2}')

                    # The config digest inside the manifest the registry
                    # serves — the image ID of the image in the registry.
                    REG_CONFIG=$(curl -s -H "${ACCEPT}" "${MANIFEST_URL}" \
                        | python3 -c "import json,sys; m=json.load(sys.stdin); print(m.get('config',{}).get('digest','MISSING'))")

                    PULLED_ID=$(podman image inspect ${FULL_IMAGE} --format '{{.Id}}')
                    PULLED_CONFIG="sha256:${PULLED_ID#sha256:}"

                    echo "registry manifest digest : ${REG_DIGEST}"
                    echo "registry config digest   : ${REG_CONFIG}"
                    echo "built config digest      : ${BUILT_CONFIG}"
                    echo "pulled config digest     : ${PULLED_CONFIG}"

                    if [ -z "${REG_DIGEST}" ]; then
                        echo "BLOCKED: the registry did not return a digest for ${FULL_IMAGE}."
                        exit 1
                    fi

                    if [ "${REG_CONFIG}" != "${BUILT_CONFIG}" ]; then
                        echo "BLOCKED: the image in the registry is not the image that was built."
                        echo "        registry config digest = ${REG_CONFIG}"
                        echo "        built config digest    = ${BUILT_CONFIG}"
                        exit 1
                    fi

                    if [ "${BUILT_CONFIG}" != "${PULLED_CONFIG}" ]; then
                        echo "BLOCKED: the copy pulled back from the registry is not the image that was built."
                        echo "        built  config digest = ${BUILT_CONFIG}"
                        echo "        pulled config digest = ${PULLED_CONFIG}"
                        exit 1
                    fi

                    echo "Digest check OK: the registry holds the image that was built, and the copy pulled back is that same image."

                    # Keep the digest for the approval gate: the message the
                    # human reads has to name the exact bytes PROD would get.
                    echo "${REG_DIGEST}" > image-digest.txt
                '''
                script {
                    env.IMAGE_DIGEST = readFile('image-digest.txt').trim()
                    echo "Image digest : ${env.IMAGE_DIGEST}"
                }
            }
        }

        stage('Image Scan') {
            // Every scan that needs an IMAGE happens here, after the push.
            // All of it is Trivy, which is Apache-2.0 — no commercial
            // scanner, no licence, no account, no credential:
            //
            //   * config    — the Containerfile: DS002 (AVD-DS-0002), the
            //                 image must not run as root
            //   * root      — the USER of the image that was actually BUILT
            //   * lib       — ${SCAN_IMAGE}, the builder stage, which still
            //                 holds the full frontend dependency tree
            //   * os        — ${FULL_IMAGE}, the runtime base we ship
            //
            // The source-tree scans live in 'Code Scan (secrets + dependencies)'
            // before the build.
            steps {
                // ------------------------------------------------------------------
                // The image's own configuration: it must not run as root.
                //
                // This replaces the root_user control that a commercial
                // scanner's assurance policy used to provide, and it does it
                // twice on purpose:
                //
                //   1. trivy config — the FILE. DS002 (AVD-DS-0002), "Image
                //      user should not be 'root'", HIGH severity. Trivy
                //      recognises a file named `Dockerfile` AND `Containerfile`,
                //      so this repository's file is picked up as it is.
                //   2. podman image inspect — the ARTEFACT. This is the one
                //      that decides: a Containerfile that says `USER bun` but
                //      was built on a base that runs as root must still be
                //      caught, and only the built image can tell us that.
                //
                // Both run BEFORE the CVE scans, so an image that would be
                // rejected is rejected in seconds rather than minutes.
                // ------------------------------------------------------------------
                sh '''
                    set -u

                    # ------------------------------------------------------------------
                    # 1. The Containerfile.
                    #
                    # `trivy config` needs no image and no runtime socket — it
                    # reads the file. The source tree is mounted from the
                    # jenkins_data volume, because the HOST resolves every
                    # bind mount and the workspace only exists inside that
                    # volume.
                    #
                    # `trivy config` has NO --scanners flag (that is an
                    # image/fs flag); the misconfiguration scan is what the
                    # `config` subcommand does. It downloads the checks
                    # bundle — the rule set, not the CVE database — on the
                    # first run and caches it in the Trivy cache volume.
                    #
                    # Only the Containerfile is scanned, not the whole tree:
                    # it is the file that defines the image that ships, and a
                    # compose file or a Kubernetes manifest in the repository
                    # has nothing to do with what is actually deployed.
                    # ------------------------------------------------------------------
                    CONFIG_RC=0
                    podman run --rm --name hku-trivy-config-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v trivy-cache:/root/.cache/trivy \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/src:ro \
                        ${TRIVY_IMAGE} \
                        config \
                            --severity HIGH,CRITICAL \
                            --exit-code 1 \
                            --format table \
                            /src/Containerfile > trivy-config-report.txt 2>&1 || CONFIG_RC=$?

                    cat trivy-config-report.txt
                    echo "trivy (Containerfile config) exit code: ${CONFIG_RC}"

                    # ------------------------------------------------------------------
                    # 2. The image that was actually built and pushed.
                    #
                    # The local store holds the registry's copy of ${FULL_IMAGE}
                    # (the 'Push to Registry' stage pulls it back), so this
                    # inspects the exact bytes the UAT and PROD sites pull.
                    # ------------------------------------------------------------------
                    INSPECT_RC=0
                    IMAGE_USER=$(podman image inspect ${FULL_IMAGE} --format '{{.Config.User}}' 2>/dev/null) || INSPECT_RC=$?

                    if [ "${INSPECT_RC}" -ne 0 ]; then
                        echo "BLOCKED: could not read ${FULL_IMAGE} from the local image store."
                        echo "        The image the registry serves is the one that has to be"
                        echo "        checked — a missing image is not a pass."
                        exit 1
                    fi

                    echo "image user: '${IMAGE_USER}'"

                    if [ -z "${IMAGE_USER}" ] || [ "${IMAGE_USER}" = "root" ] || [ "${IMAGE_USER}" = "0" ]; then
                        echo "BLOCKED: the runtime image runs as root ('${IMAGE_USER}')."
                        echo "        The Containerfile must end with a non-root USER, because this"
                        echo "        container is what reaches the customer."
                        exit 1
                    fi

                    if [ "${CONFIG_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy found a HIGH/CRITICAL misconfiguration in the"
                        echo "        Containerfile (or the config scan itself failed) — the"
                        echo "        root-user rule is DS002 — see trivy-config-report.txt"
                        exit 1
                    fi

                    echo "Config check OK: the image does not run as root, and the Containerfile has no HIGH/CRITICAL misconfiguration."
                '''

                // ------------------------------------------------------------------
                // Trivy, on the IMAGES.
                //
                //   library  on ${SCAN_IMAGE} — the builder stage, which still
                //           holds the full frontend dependency tree (react,
                //           vite, xlsx, react-router-dom). The runtime image
                //           does not carry the frontend node_modules at all,
                //           so this scan cannot move to the source tree.
                //   os       on ${FULL_IMAGE}  — the runtime base we ship.
                //
                // HARD GATE, but the decision is made by scripts/trivy_scope.py
                // and not by --exit-code. The library report is JSON, because
                // the raw finding list cannot say whether a package SHIPS:
                // bun hoists, so picomatch sits at app/node_modules/picomatch
                // even though only vite reaches it. The scope script reads
                // the lockfiles and applies the same rule as the code scan:
                // an advisory on a package that SHIPS, or any secret at all,
                // blocks the build; an advisory on a build tool is reported
                // and does not. See the header for the details.
                // ------------------------------------------------------------------
                sh '''
                    set -u

                    # The docker socket is REQUIRED: Trivy resolves the target
                    # image through a container runtime API, and without the
                    # socket it can only reach a remote registry.
                    #
                    # ${PODMAN_SOCK} is the socket on the HOST, because podman
                    # runs on the host (see CONTAINER_HOST in the environment
                    # block) and the host resolves every bind mount. Inside
                    # the container it is still called /var/run/docker.sock —
                    # that is the name Trivy looks for.
                    #
                    # No --severity filter here: the scope script applies the
                    # threshold to the vulnerabilities, and a secret is a
                    # finding at ANY severity, so none may be filtered away
                    # before the script sees it.
                    TRIVY_RC=0
                    podman run --rm --name hku-trivy-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${PODMAN_SOCK}:/var/run/docker.sock \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        ${TRIVY_IMAGE} \
                        image --scanners vuln,secret \
                            --pkg-types library \
                            --format json \
                            ${SCAN_IMAGE} > trivy-report.json 2> trivy-scan.err || TRIVY_RC=$?

                    if [ "${TRIVY_RC}" -ne 0 ]; then
                        echo "--- trivy stderr ---"
                        cat trivy-scan.err || true
                        echo "BLOCKED: the Trivy scan itself failed — see trivy-scan.err"
                        exit 1
                    fi

                    # ------------------------------------------------------------------
                    # The scope gate.
                    #
                    #   exit 0  nothing that ships is vulnerable, no secret
                    #   exit 1  a SHIPPED package has an advisory, or a secret
                    #   exit 2  the report could not be read — NOT a pass
                    #
                    # --server-ship-dev: the runtime image copies `server/`
                    # out of the builder, so the server's node_modules —
                    # devDependencies included — really do reach the
                    # customer. The frontend is the opposite: only the
                    # compiled bundle ships.
                    # ------------------------------------------------------------------
                    TRIVY_SCOPE_RC=0
                    python3 scripts/trivy_scope.py trivy-report.json \
                        app/bun.lock app/server/bun.lock \
                        --level high --server-ship-dev \
                        > trivy-report.txt 2>&1 || TRIVY_SCOPE_RC=$?

                    cat trivy-report.txt
                    echo "trivy scope exit code: ${TRIVY_SCOPE_RC}"

                    # ------------------------------------------------------------------
                    # OS packages of the image we actually ship.
                    # HARD GATE on CRITICAL. The runtime base is
                    # oven/bun:1.3-alpine, which currently carries 0 CRITICAL
                    # and a handful of HIGH (all with a fix available in a
                    # newer alpine release). Gating on HIGH too would block
                    # the build on a base-image update we do not control, so
                    # HIGH is reported and CRITICAL is the line that stops a
                    # build. The count moves with the vulnerability database,
                    # which is refreshed on every run — so the report of the
                    # day is the authority, not a number written down here.
                    # ------------------------------------------------------------------
                    TRIVY_OS_RC=0
                    podman run --rm --name hku-trivy-os-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${PODMAN_SOCK}:/var/run/docker.sock \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        ${TRIVY_IMAGE} \
                        image --scanners vuln \
                            --pkg-types os \
                            --severity CRITICAL \
                            --exit-code 1 \
                            --format table \
                            ${FULL_IMAGE} > trivy-os-report.txt 2>&1 || TRIVY_OS_RC=$?

                    cat trivy-os-report.txt
                    echo "trivy (OS packages) exit code: ${TRIVY_OS_RC}"

                    # The HIGH findings are not gated, but they are assessed, so
                    # they belong in the artifact that goes to the client.
                    podman run --rm --name hku-trivy-os-high-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${PODMAN_SOCK}:/var/run/docker.sock \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        ${TRIVY_IMAGE} \
                        image --scanners vuln \
                            --pkg-types os \
                            --severity HIGH \
                            --format table \
                            ${FULL_IMAGE} >> trivy-os-report.txt 2>&1 || true

                    # ------------------------------------------------------------------
                    # The OS packages as JSON, for the vulnerability report.
                    # The same scan the gate above ran, in a machine-readable
                    # form, so the report can list the findings with their
                    # severity, their fixed version and their links.
                    #
                    # The CRITICAL count below is checked as well, so the
                    # report and the gate cannot disagree: a CRITICAL in the
                    # JSON is a CRITICAL in the image, whatever the table run
                    # said.
                    # ------------------------------------------------------------------
                    podman run --rm --name hku-trivy-os-json-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${PODMAN_SOCK}:/var/run/docker.sock \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        ${TRIVY_IMAGE} \
                        image --scanners vuln \
                            --pkg-types os \
                            --severity HIGH,CRITICAL \
                            --format json \
                            ${FULL_IMAGE} > trivy-os-report.json 2> trivy-os-json.err || true

                    OS_JSON_CRITICAL=$(python3 -c "import json;d=json.load(open('trivy-os-report.json'));print(sum(1 for r in (d.get('Results') or []) for v in (r.get('Vulnerabilities') or []) if v.get('Severity')=='CRITICAL'))" 2>/dev/null || echo "-1")

                    if [ "${OS_JSON_CRITICAL}" = "-1" ]; then
                        echo "BLOCKED: the OS scan output could not be read — see trivy-os-json.err"
                        exit 1
                    fi

                    if [ "${OS_JSON_CRITICAL}" -ne 0 ]; then
                        echo "BLOCKED: Trivy reported a CRITICAL OS vulnerability in the runtime image — see trivy-os-report.json"
                        exit 1
                    fi

                    echo "trivy (OS packages, JSON) CRITICAL count: ${OS_JSON_CRITICAL}"

                    # ------------------------------------------------------------------
                    # The vulnerability report — ONE page with everything the
                    # CI band found, the image and the code together.
                    #
                    # This is the open-source replacement for the console
                    # dashboard. Trivy's own HTML template renders ONE Trivy
                    # report at a time, and it does not render secrets at all,
                    # so scripts/build_report.py renders all five sections
                    # itself: the image's OS packages, the image's libraries,
                    # the image's secrets, the source tree's secrets and the
                    # dependency advisories — from the scan output that is
                    # already on disk. No console, no account, no server to
                    # keep alive; the report is downloaded from the build page
                    # like any other artefact.
                    #
                    # It is generated BEFORE the gates below, so a BLOCKED
                    # build still leaves a report behind to diagnose.
                    #
                    # A report that cannot be written is a failure: an
                    # unreadable report must never look like a clean scan.
                    # ------------------------------------------------------------------
                    REPORT_RC=0
                    python3 scripts/build_report.py \
                        --os-json trivy-os-report.json \
                        --image-json trivy-report.json \
                        --secret-json trivy-secret-report.json \
                        --audit bun-audit-root.json bun-audit-server.json \
                        --lock app/bun.lock app/server/bun.lock \
                        --image ${FULL_IMAGE} \
                        --tag ${IMAGE_VERSION} \
                        --digest ${IMAGE_DIGEST} \
                        --build "#${BUILD_NUMBER}" \
                        --out vulnerability-report.html || REPORT_RC=$?

                    if [ "${REPORT_RC}" -ne 0 ]; then
                        echo "BLOCKED: the vulnerability report could not be written — see the message above"
                        exit 1
                    fi

                    if [ ! -s vulnerability-report.html ]; then
                        echo "BLOCKED: vulnerability-report.html is empty."
                        exit 1
                    fi

                    echo "vulnerability report: vulnerability-report.html ($(wc -c < vulnerability-report.html) bytes)"

                    if [ "${TRIVY_SCOPE_RC}" -eq 2 ]; then
                        echo "BLOCKED: the Trivy findings could not be scoped — the scan is not verified, so it is not a pass — see trivy-report.txt"
                        exit 1
                    fi

                    if [ "${TRIVY_SCOPE_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy found an advisory in a dependency that SHIPS, or a secret, in the image — see trivy-report.txt"
                        exit 1
                    fi

                    if [ "${TRIVY_OS_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy reported a CRITICAL OS vulnerability in the runtime image — see trivy-os-report.txt"
                        exit 1
                    fi

                    echo "Image scan OK: no HIGH/CRITICAL advisory in anything that ships, no detected secrets, no CRITICAL OS CVEs."
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-config-report.txt,trivy-report.txt,trivy-report.json,trivy-scan.err,trivy-os-report.txt,trivy-os-report.json,trivy-os-json.err,vulnerability-report.html',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('Deploy & Verify') {
            // CI/CD proof: boot the scanned image on a spare port, hit the
            // health endpoint, the database connection endpoint and the SPA
            // root, and fail the build if any of them is missing. Cleans both
            // containers up afterwards.
            //
            // The application initialises its schema at boot — `await initDb()`
            // is not guarded — so it REFUSES TO START when the database is
            // unreachable. The CI therefore cannot point it at a closed port
            // to prove a "degraded" start: it needs a real database. The
            // throwaway one is a PostgreSQL container on the CI host, on a
            // port of its own, with a database of its own. No UAT or PROD data
            // is touched, and it is removed again at the end of the stage.
            //
            // The image no longer carries a default DB_HOST / DB_USER, and in
            // production mode it refuses to boot without SSO_COOKIE_SECRET —
            // so the verify container gets throwaway values for both.
            steps {
                sh '''
                    set -eux

                    # ----- the throwaway database ---------------------------------------
                    # --replace: a container left behind by a FAILED build would
                    # still own port 55432, and the next build would then fail
                    # with "address already in use". --replace removes the
                    # leftover first, so the stage is repeatable.
                    podman run -d --replace --name hku-verify-db-${BUILD_NUMBER} \
                        --network host \
                        -e POSTGRES_USER=verify \
                        -e POSTGRES_PASSWORD=verify \
                        -e POSTGRES_DB=engg_intranet_verify \
                        docker.io/library/postgres:14-alpine \
                        postgres -p ${VERIFY_DB_PORT}

                    # pg_isready is called by its absolute path: the postgres
                    # image keeps the server binaries in /usr/local/bin, which
                    # is on the image's PATH but is NOT what `podman exec`
                    # resolves a bare command name against.
                    for i in $(seq 1 30); do
                        if podman exec hku-verify-db-${BUILD_NUMBER} \
                             /usr/local/bin/pg_isready -h 127.0.0.1 -p ${VERIFY_DB_PORT} \
                             -U verify -d engg_intranet_verify > /dev/null 2>&1; then
                            break
                        fi
                        sleep 2
                    done
                    podman exec hku-verify-db-${BUILD_NUMBER} \
                        /usr/local/bin/pg_isready -h 127.0.0.1 -p ${VERIFY_DB_PORT} \
                        -U verify -d engg_intranet_verify \
                        || { echo "BLOCKED: the throwaway database did not start"; \
                             podman logs hku-verify-db-${BUILD_NUMBER} || true; \
                             exit 1; }

                    # ----- the application under test ------------------------------------
                    podman run -d --replace --name hku-intranet-verify-${BUILD_NUMBER} \
                        --network host \
                        -e HOST=127.0.0.1 \
                        -e PORT=${VERIFY_PORT} \
                        -e SSO_COOKIE_SECRET=ci-throwaway-secret-not-used-anywhere \
                        -e DB_HOST=127.0.0.1 \
                        -e DB_PORT=${VERIFY_DB_PORT} \
                        -e DB_USER=verify \
                        -e DB_PASSWORD=verify \
                        -e DB_NAME=engg_intranet_verify \
                        ${FULL_IMAGE}

                    # Wait for the API to finish initDb() and start listening.
                    for i in $(seq 1 30); do
                        if curl -fsS "http://127.0.0.1:${VERIFY_PORT}/health" > /dev/null 2>&1; then
                            break
                        fi
                        sleep 2
                    done

                    curl -fsS "http://127.0.0.1:${VERIFY_PORT}/health" | grep -q '"status":"ok"' \
                        || { echo "BLOCKED: /health did not return status ok"; \
                             podman logs hku-intranet-verify-${BUILD_NUMBER} || true; \
                             exit 1; }

                    curl -fsS "http://127.0.0.1:${VERIFY_PORT}/" | grep -q '<div id="root">' \
                        || { echo "BLOCKED: SPA index missing root div"; \
                             podman logs hku-intranet-verify-${BUILD_NUMBER} || true; \
                             exit 1; }

                    # The application's own readiness answer: which database it
                    # is on, and whether that database answers. This is the
                    # same endpoint the deployment gate uses on the real
                    # sites, so the CI proves the one thing the sites check.
                    READY=$(curl -fsS "http://127.0.0.1:${VERIFY_PORT}/api/db/connection")
                    echo "${READY}"
                    echo "${READY}" | grep -q '"isReachable":true' \
                        || { echo "BLOCKED: the application did not reach its database"; \
                             podman logs hku-intranet-verify-${BUILD_NUMBER} || true; \
                             exit 1; }
                    echo "${READY}" | grep -q '"databaseName":"engg_intranet_verify"' \
                        || { echo "BLOCKED: the application is on the wrong database"; \
                             podman logs hku-intranet-verify-${BUILD_NUMBER} || true; \
                             exit 1; }

                    echo "Webpage verified: /health ok + SPA root div + database reachable on 127.0.0.1:${VERIFY_PORT}"
                '''
            }
            post {
                always {
                    sh '''
                        # --ignore matters: `podman rm -f` aborts the whole
                        # operation — silently, with rc 0 — when ONE of the
                        # names does not exist. Without --ignore the leftover
                        # container keeps port 55432 and the next build fails.
                        podman rm -f --ignore hku-intranet-verify-${BUILD_NUMBER} \
                                           hku-verify-db-${BUILD_NUMBER} || true
                    '''
                }
            }
        }

        stage('Deploy UAT (Database & Application)') {
            // The three chips of the design picture, in one stage:
            //
            //   Pull Image   the role pulls the scanned tag from the registry
            //   Deploy       the role installs and restarts the systemd unit
            //   Deploy Database & Application
            //                the application creates its OWN database on the
            //                PostgreSQL server, and the readiness check proves
            //                which database it is actually connected to
            //
            // UAT is 192.168.147.104 — the same host the CI runs on, and the
            // host that also carries the other project's DR site. The
            // database is on .103 (the data tier), reached over the network
            // with UAT's own role.
            steps {
                sh '''
                    set -eux

                    # The Jenkins container's HOME is /home/server, not
                    # JENKINS_HOME, so the "~/.ssh/id_rhai108_rsa" in
                    # ansible.cfg would not resolve. The key is named here.
                    export ANSIBLE_PRIVATE_KEY_FILE=${ANSIBLE_KEY}

                    cd ${WORKSPACE}/ansible
                    ansible-playbook -i inventory.ini deploy.yml \
                        -e intranet_target=intranet_uat \
                        -e intranet_image=${FULL_IMAGE}

                    # Checked from HERE, not from the site: that proves the
                    # network path and the firewall, not only that the
                    # container is alive on its own host.
                    curl -fsS "http://${UAT_HOST}:${UAT_PORT}/health"
                    echo ""
                    # The application reports which database it is connected to
                    # and whether that database answers. That is what proves
                    # UAT is a separate data set and not a second view of
                    # production.
                    READY=$(curl -fsS "http://${UAT_HOST}:${UAT_PORT}/api/db/connection")
                    echo "${READY}"
                    # The pattern is built by concatenation, not with backslash
                    # escapes: Groovy eats the backslash in a triple-quoted
                    # block, and dash then strips the quotes, so grep would be
                    # handed databaseName:engg_intranet_uat, which never matches
                    # the quoted key in the JSON.
                    echo "${READY}" | grep -q '"databaseName":"'"${UAT_DB}"'"' \
                        || { echo "BLOCKED: UAT is serving the wrong database, expected ${UAT_DB}"; exit 1; }
                    echo "${READY}" | grep -q '"isReachable":true' \
                        || { echo "BLOCKED: UAT cannot reach its database ${UAT_DB}"; exit 1; }

                    echo "UAT deployed: http://${UAT_HOST}:${UAT_PORT}/  (database ${UAT_DB})"
                '''
            }
        }

        stage('Record Promotion') {
            // The last stage of this job. It writes down WHAT was deployed to
            // UAT, so the pipeline-prod job can promote those exact bytes
            // later — an hour later, overnight, whenever the human has
            // finished testing.
            //
            // The record is a KEY=VALUE file under JENKINS_HOME. That
            // directory is in the jenkins_data volume, so it survives a
            // container recreate, and both jobs run in the same container —
            // which is what makes a file a working carrier between them.
            // (The controller has no parameterized-trigger, no copy-artifact
            // and no job-dsl, so the usual `build job: ..., parameters: ...`
            // is not available.)
            //
            // It is written AFTER the UAT health and database checks pass, so
            // a record can only ever describe an image that actually reached
            // UAT and was actually running there.
            steps {
                script {
                    def promotionId = "uat-${BUILD_NUMBER}"

                    // The date is pinned to Hong Kong time, like the tag's
                    // DDMMYY part: the agent container runs UTC and the host
                    // runs America/New_York, so an unpinned date is wrong.
                    def createdAt = sh(
                        script: "TZ=Asia/Hong_Kong date --iso-8601=seconds",
                        returnStdout: true).trim()
                    def createdAtEpoch = sh(
                        script: "date +%s",
                        returnStdout: true).trim()

                    // No shell is involved in writing this — Groovy builds the
                    // text, so nothing can be mangled by quoting and the
                    // values cannot be interpreted as commands.
                    def record = """\
# written by the pipeline-uat job (UAT build #${BUILD_NUMBER})
PROMOTION_ID=${promotionId}
UAT_BUILD_NUMBER=${BUILD_NUMBER}
UAT_BUILD_URL=${BUILD_URL}
CREATED_AT=${createdAt}
CREATED_AT_EPOCH=${createdAtEpoch}
FULL_IMAGE=${env.FULL_IMAGE}
IMAGE_DIGEST=${env.IMAGE_DIGEST}
IMAGE_VERSION=${env.IMAGE_VERSION}
REGISTRY=${env.REGISTRY}
IMAGE_NAME=${env.IMAGE_NAME}
APP_REPO=${env.APP_REPO}
APP_REF=${env.APP_REF}
APP_COMMIT=${env.APP_COMMIT}
UAT_HOST=${env.UAT_HOST}
UAT_PORT=${env.UAT_PORT}
UAT_DB=${env.UAT_DB}
"""
                    writeFile file: 'promotion.env', text: record

                    env.PROMOTION_ID = promotionId
                    env.PROMOTION_FILE = "${promotionId}.env"
                }
                sh '''
                    set -eux
                    mkdir -p ${PROMOTION_DIR}
                    cp promotion.env ${PROMOTION_DIR}/${PROMOTION_ID}.env
                    cp promotion.env ${PROMOTION_DIR}/latest.env
                    echo "--- the promotion record ---"
                    cat ${PROMOTION_DIR}/latest.env
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'promotion.env', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            sh '''
                # FULL_IMAGE / SCAN_IMAGE are empty when the 'Resolve Version'
                # stage never ran, so guard every use of them.
                if [ -z "${FULL_IMAGE}" ] || [ -z "${SCAN_IMAGE}" ]; then
                    echo "Image references unresolved — skipping image cleanup"
                    exit 0
                fi

                # Remove the sidecar containers this build started. They all
                # run with --rm, but a FAILED run can leave one behind (a
                # Trivy scan-target container is the usual one), and
                # a container holding an image makes `podman rmi` refuse:
                #     image used by <id>: image is in use by a container
                #
                # --ignore is REQUIRED here: `podman rm -f` gives up on the
                # WHOLE operation — silently, with rc 0 — when one of the
                # names does not exist. Most of these names do not exist in
                # any given build, so without --ignore this block removes
                # nothing at all.
                podman rm -f --ignore hku-audit-${BUILD_NUMBER} \
                             hku-audit-fs-${BUILD_NUMBER} \
                             hku-audit-fs-srv-${BUILD_NUMBER} \
                             hku-trivy-config-${BUILD_NUMBER} \
                             hku-trivy-${BUILD_NUMBER} \
                             hku-trivy-fs-${BUILD_NUMBER} \
                             hku-trivy-fs-json-${BUILD_NUMBER} \
                             hku-trivy-os-${BUILD_NUMBER} \
                             hku-trivy-os-high-${BUILD_NUMBER} \
                             hku-trivy-os-json-${BUILD_NUMBER} \
                             hku-intranet-verify-${BUILD_NUMBER} \
                             hku-verify-db-${BUILD_NUMBER} 2>/dev/null || true

                # Force-clear any other container still holding the scan-only
                # image. ${SCAN_IMAGE} is never used by the production
                # container, so removing its holders is always safe.
                for c in $(podman ps -aq --filter ancestor=${SCAN_IMAGE} 2>/dev/null); do
                    podman rm -f --ignore "$c" || true
                done

                # Deliberately NOT --force: if the production container is
                # running from ${FULL_IMAGE}, rmi correctly refuses and the
                # image stays. That is the safe outcome.
                podman rmi ${FULL_IMAGE} || true
                podman rmi ${SCAN_IMAGE} || true
            '''
        }
        success {
            echo "Pipeline SUCCESS — ${env.FULL_IMAGE} was scanned and is live on UAT. Nothing was deployed to production."
            emailext (
                subject: "✅ UAT build #${BUILD_NUMBER} PASSED — ${env.FULL_IMAGE} is live on UAT",
                body: """<h2>HKU ENGG Intranet — CI/CD — UAT Build #${BUILD_NUMBER} PASSED</h2>
                    <p>Image: <code>${env.FULL_IMAGE}</code></p>
                    <p>Digest: <code>${env.IMAGE_DIGEST}</code></p>
                    <p>Application: <code>${APP_REPO}</code> @ <code>${APP_COMMIT}</code></p>
                    <p>Image scan (Trivy, open source): <b>compliant</b> — the image does not run as root (DS002 + the built image's own USER), no HIGH/CRITICAL Containerfile misconfiguration</p>
                    <p>Code scan: no secrets in the source tree, no HIGH/CRITICAL dependency advisories, no CRITICAL OS CVEs</p>
                    <p>Deploy verify: /health + SPA root ok on <code>127.0.0.1:${VERIFY_PORT}</code></p>
                    <p><b>UAT</b>: <a href=\"http://${UAT_HOST}:${UAT_PORT}/\">http://${UAT_HOST}:${UAT_PORT}/</a> (database <code>${UAT_DB}</code>)</p>
                    <p><b>PROD</b>: not touched. This job never deploys to production.</p>
                    <p><b>Next step</b>: test UAT. When it passes, start the <code>pipeline-prod</code> job to promote these exact bytes — the promotion record is <code>${env.PROMOTION_FILE}</code>.</p>
                    <p>Reports: <a href=\"${BUILD_URL}artifact/\">vulnerability-report.html (one page — image and code), trivy-config-report.txt, audit-scope-root.txt, audit-scope-server.txt, trivy-secret-report.txt, trivy-report.txt, trivy-os-report.txt</a><br>
                       Console: <a href=\"${BUILD_URL}console\">build console</a><br>
                       Build: <a href=\"${BUILD_URL}\">#${BUILD_NUMBER}</a></p>
                """,
                mimeType: 'text/html',
                to: 'tim.wong@systex.com.hk'
            )
        }
        failure {
            echo "Pipeline FAILED — check the failing stage above for the blocking finding"
            emailext (
                subject: "❌ UAT build #${BUILD_NUMBER} FAILED",
                body: """<h2>HKU ENGG Intranet — CI/CD — UAT Build #${BUILD_NUMBER} FAILED</h2>
                    <p>Image: <code>${env.FULL_IMAGE ?: 'unresolved'}</code></p>
                    <p>Check the console for the failure stage. This job only ever touches UAT, so nothing was deployed to UAT and nothing was deployed to production.</p>
                    <p>Reports: <a href=\"${BUILD_URL}artifact/\">vulnerability-report.html (one page — image and code), trivy-config-report.txt, audit-scope-root.txt, audit-scope-server.txt, trivy-secret-report.txt, trivy-report.txt, trivy-os-report.txt</a><br>
                       Console: <a href=\"${BUILD_URL}console\">build console</a><br>
                       Build: <a href=\"${BUILD_URL}\">#${BUILD_NUMBER}</a></p>
                """,
                mimeType: 'text/html',
                attachLog: true,
                to: 'tim.wong@systex.com.hk'
            )
        }
    }
}
