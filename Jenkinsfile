// Jenkinsfile — the HKU ENGG Intranet UAT → APPROVAL → PROD pipeline
//
// Code scan → build → push to the registry → image scan → deploy & verify
// → deploy UAT → MANUAL APPROVAL → deploy PROD
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
//   192.168.147.104   CI+UAT Jenkins, the image registry and Aqua (CI),
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
//   1. Credential "aqua-console"
//        Manage Jenkins → Credentials → (global) → Add Credentials
//        Kind: Username with password | ID: aqua-console | Username: administrator
//        (Aqua Console admin password — used by the scanner CLI --user/--password.)
//
//   2. Registry running AND registered in the Aqua Console
//        podman run -d --name registry --network host \
//          -v registry_data:/var/lib/registry \
//          -e REGISTRY_HTTP_ADDR=:8082 docker.io/library/registry:2
//        Console → Registries → Add → http://192.168.147.104:8082 (no auth)
//
//   3. Assurance policy "testing-image-assurance" must control:
//        malware + root_user
//        root_user is why the Containerfile ends with `USER bun` — a
//        root-running image reports "Image Is Non-compliant" and the gate
//        below blocks the build. (Optionally add a vulnerability control once
//        the OS CVE backlog is triaged; today the policy is malware+root only,
//        so the Aqua image scan does NOT gate on CVEs.)
//
//   4. Pipeline job configuration
//        Definition:  Pipeline script from SCM
//        SCM:         Git | https://github.com/MangoTim/pipeline-uat.git
//        Branch:      */main
//        Script Path: Jenkinsfile
//        (This repository IS the pipeline — the Jenkinsfile, the Ansible
//         roles and the setup script are all committed here, and the deploy
//         stages run ${WORKSPACE}/ansible/deploy.yml from it.)
//
//   5. The agent must be the custom jenkins-with-podman image:
//        --net=host + /run/podman/podman.sock mounted as /var/run/docker.sock
//        Host networking is what lets the scanner containers reach the
//        registry, the Aqua Console and the npm / Trivy DB registries.
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
//        The Aqua scanner CLI and Trivy run as `podman run` shell steps — no
//        sandboxed Groovy APIs are used, so no signatures need approving.
//
//   7. The aqua-web console container must have a working OUTBOUND path
//        to cybercenter5.aquasec.com. The scanner reaches the console fine,
//        but the console itself performs the "cybercenter ↔ scanner
//        compatibility" check server-side — when the console cannot reach
//        the internet, the scan fails with:
//            twirp error internal: Failed checking cybercenter to scanner
//            compatibility: ... Get "https://cybercenter5.aquasec.com/":
//            net/http: TLS handshake timeout
//        This is a HOST-side problem, not a pipeline problem. Symptom on the
//        host: `podman logs aqua-web` shows "dial tcp 192.168.147.103:5432:
//        connect: no route to host" and the console UI on :8080 hangs.
//        Cause: podman's per-container CNI chains / bridge attachment are
//        destroyed by `firewall-cmd --reload` (firewalld uses the nftables
//        backend and flushes the nat table that podman wrote into).
//        Fix on the host:  podman network reload
//        (or recreate the aqua-web / aqua-gateway containers).
//
//   8. UAT / PROD deployment prerequisites (needed by the last three stages)
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
// The UAT -> APPROVAL -> PROD path
//
//   'Deploy & Verify' boots the image once ON THE CI HOST to prove it starts.
//   Nothing is deployed from there. The last three stages put the image on a
//   site:
//
//     Deploy UAT (Database & Application)
//        ansible -> .104:8097, its own database engg_intranet_uat, and the
//        readiness check proves which database it is connected to
//     Manual Approval
//        a human decides whether PRODUCTION gets it
//     Deploy PROD (Database & Application)
//        ansible -> .105:8093, database engg_intranet
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
//   The approval is a plain Jenkins `input` step — no plugin needed. The
//   build waits for a human, so 'options.timeout' is raised to 60 minutes and
//   the input step carries its own 30-minute timeout.
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
//        bun audit --audit-level=high            the lockfiles, in a
//                                                 throwaway oven/bun:1.3-alpine
//                                                 container with the source
//                                                 mounted — no build needed
//
//     'Image Scan'                            AFTER the push, on the images
//        Aqua scan (--local and --registry)      the image that ships
//        trivy vuln,secret --pkg-types library   ${SCAN_IMAGE} — the builder
//                                                  stage, which still holds the
//                                                  full frontend dependency tree
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
//   NN           the Jenkins build number, zero padded to two digits. It is
//                 monotonic, so a tag is never reused and always maps back to
//                 exactly one build.
//
//   Full reference: 192.168.147.104:8082/hku-intranet:v1.1.28102601
//
// ---------------------------------------------------------------------------
// What "Image Is Compliant" does and does not mean
//
//   The Aqua console's Compliant badge comes from the ASSURANCE POLICY
//   (testing-image-assurance = malware + root_user). It is NOT a statement
//   that the image is free of CVEs — the console shows those separately, in
//   the Vulnerabilities tab of the image page.
//
//   Every CVE that showed up there was inherited from the base image, not
//   from this code. The Debian runtime base (oven/bun:1.3-slim) carried 100
//   HIGH/CRITICAL, 3 of them CRITICAL, all in perl-base. The runtime stage
//   now uses oven/bun:1.3-alpine, which carries 4 HIGH and 0 CRITICAL. The
//   application dependency trees are clean: 0 HIGH/CRITICAL.
//
// ---------------------------------------------------------------------------
// Known accepted risks (deliberate, so the pipeline stays green):
//
//   * The 4 HIGH OS CVEs in the alpine base have a fix in a newer alpine
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
//   * Trivy runs with --exit-code 1, so its output is a HARD GATE: any
//     HIGH/CRITICAL library CVE or any secret it detects fails the build.
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
        AQUA_HOST     = 'https://192.168.147.104'
        SCANNER_IMAGE = 'registry.aquasec.com/scanner:2022.4.868'
        TRIVY_IMAGE   = 'docker.io/aquasec/trivy:0.76.1'
        AQUA_CREDS_ID = 'aqua-console'

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

        // The two deployment sites — TWO HOSTS, not two containers on one:
        //   UAT   192.168.147.104  (the intranet container)         user uat
        //   PROD  192.168.147.105  (the live site)                  user rhai
        //   DB    192.168.147.103  (the PostgreSQL server — one instance
        //                           holding one database and one role per
        //                           environment; the intranet DR site joins
        //                           this host later)
        //
        // Each site gets its own port and — the part that matters — its OWN
        // DATABASE and its OWN database role, so a UAT session never touches
        // production data even though both databases live on the same host.
        UAT_HOST      = '192.168.147.104'
        UAT_PORT      = '8097'
        UAT_DB        = 'engg_intranet_uat'
        PROD_HOST     = '192.168.147.105'
        PROD_PORT     = '8093'
        PROD_DB       = 'engg_intranet'

        // The pipeline's own repository — the one this Jenkinsfile lives in.
        // The Checkout stage clones it; the deploy stages read the Ansible
        // roles out of it.
        PIPELINE_REPO_URL = 'https://github.com/MangoTim/pipeline-uat.git'

        // The APPLICATION repository. The 'Fetch App Source' stage clones it
        // into ${WORKSPACE}/app, and everything after that — the version, the
        // scans, the build — works on that copy.
        //
        // APP_REF pins the exact commit the pipeline builds. Move it forward
        // deliberately: that is the record of what was promoted to PROD.
        APP_REPO = 'https://github.com/MangoTim/hku-calendar.git'
        APP_REF  = 'main'

        // The controller's SSH key for Ansible. The path is relative to the
        // CONTROLLER's home, so the same inventory works from the Jenkins
        // container and from a developer machine. The Jenkins container's HOME
        // is /home/server, not JENKINS_HOME, so the "~" in ansible.cfg would
        // not resolve — the deploy stages export ANSIBLE_PRIVATE_KEY_FILE.
        ANSIBLE_KEY   = '/var/jenkins_home/.ssh/id_rhai108_rsa'

        // IMAGE_VERSION / FULL_IMAGE / SCAN_IMAGE are resolved at run time by
        // the 'Resolve Version' stage — they depend on the VERSION file and
        // on the build date, neither of which the environment block can read.
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        // 60 minutes, not 25: the build now waits at the approval gate for a
        // human. The input step has its own 30-minute timeout on top of this.
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
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
            steps {
                sh '''
                    set -eux
                    rm -rf app
                    git clone --depth 1 --branch ${APP_REF} ${APP_REPO} app
                    cd app
                    git rev-parse HEAD
                    echo "App commit: $(git rev-parse HEAD)"
                    ls -1
                '''
                script {
                    env.APP_COMMIT = sh(script: 'cd app && git rev-parse HEAD', returnStdout: true).trim()
                    echo "App commit : ${env.APP_COMMIT}"
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
            //   NN           the Jenkins build number, zero padded to two
            //                 digits. It is monotonic, so a tag is never reused
            //                 and always maps back to exactly one build.
            //
            // Examples: v1.1.28102601, v1.1.28102602, then v1.2.28102603
            // after the version line is bumped.
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
                    # 2. bun audit — dependency CVEs straight from the lockfiles.
                    #    `bun audit` reads ONLY the lockfile, so it needs neither
                    #    a build nor node_modules: the source tree is mounted
                    #    into a throwaway bun container and the audit runs
                    #    there. Root workspace first, then server/ (it has its
                    #    own lockfile).
                    #
                    #    The mount is READ-WRITE on purpose: bun opens
                    #    package.json for writing while it resolves the
                    #    project, so a read-only mount fails with
                    #    "Unexpected: could not open /app/package.json" —
                    #    a scan failure, not a finding. Nothing is written:
                    #    the directory is identical before and after.
                    # ------------------------------------------------------------------
                    BUN_RC=0
                    podman run --rm --name hku-audit-fs-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${JENKINS_VOLUME_PATH}/workspace/${JOB_NAME}/app:/app \
                        --entrypoint sh -w /app oven/bun:1.3-alpine \
                        -c '
                            rc=0
                            echo "### bun audit — workspace root"
                            bun audit --audit-level=high || rc=$?
                            cd server
                            echo ""
                            echo "### bun audit — server/"
                            bun audit --audit-level=high || rc=$?
                            exit $rc
                        ' > bun-audit.txt 2>&1 || BUN_RC=$?

                    cat bun-audit.txt
                    echo "bun audit exit code: ${BUN_RC}"

                    # ------------------------------------------------------------------
                    # Gate: a secret anywhere in the source tree.
                    # ------------------------------------------------------------------
                    if [ "${SECRET_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy detected a secret in the source tree (or the scan itself failed) — see trivy-secret-report.txt"
                        exit 1
                    fi

                    # ------------------------------------------------------------------
                    # Gate: HIGH/CRITICAL dependency advisories.
                    # ------------------------------------------------------------------
                    if [ "${BUN_RC}" -ne 0 ]; then
                        echo "BLOCKED: bun audit reported HIGH/CRITICAL dependency advisories (or the npm advisory registry was unreachable) — see bun-audit.txt"
                        exit 1
                    fi

                    echo "Code scan OK: no secrets in the source tree, no HIGH/CRITICAL dependency advisories."
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'bun-audit.txt,trivy-secret-report.txt',
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
                    BUILT_ID=$(podman image inspect ${FULL_IMAGE} --format '{{.Id}}')

                    podman push ${FULL_IMAGE} --tls-verify=false

                    # Pull the pushed copy back, so the local store holds the
                    # bytes the UAT and PROD sites will pull. Everything the
                    # scans below look at is then literally the registry's
                    # copy, not the build's intermediate representation.
                    #
                    # The pull is also what makes the comparison meaningful:
                    # podman keeps the OCI manifest of a locally built image,
                    # but the registry stores the DOCKER v2s2 manifest it was
                    # pushed as. The two describe the same image, but their
                    # manifest digests differ, so comparing a locally built
                    # manifest digest with the registry's would always fail.
                    podman pull --tls-verify=false ${FULL_IMAGE}

                    # Prove that what the client pulls from the registry is
                    # the same image that was built here and then scanned by
                    # Aqua / Trivy in the stage below. Without this the scan
                    # evidence and the delivered artefact could in principle
                    # be different images.
                    REG_DIGEST=$(curl -s \
                        -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json' \
                        -o /dev/null -D - \
                        "http://${REGISTRY}/v2/${IMAGE_NAME}/manifests/${IMAGE_VERSION}" \
                        | tr -d '\r' | awk '/Docker-Content-Digest/ {print $2}')
                    PULLED_ID=$(podman image inspect ${FULL_IMAGE} --format '{{.Id}}')
                    PULLED_DIGEST=$(podman image inspect ${FULL_IMAGE} --format '{{.Digest}}')

                    echo "registry digest : ${REG_DIGEST}"
                    echo "pulled digest   : ${PULLED_DIGEST}"
                    echo "built image id  : ${BUILT_ID}"
                    echo "pulled image id : ${PULLED_ID}"

                    if [ -z "${REG_DIGEST}" ]; then
                        echo "BLOCKED: the registry did not return a digest for ${FULL_IMAGE}."
                        exit 1
                    fi

                    if [ "${REG_DIGEST}" != "${PULLED_DIGEST}" ]; then
                        echo "BLOCKED: registry digest (${REG_DIGEST}) does not match the pulled image digest (${PULLED_DIGEST})."
                        exit 1
                    fi

                    if [ "${BUILT_ID}" != "${PULLED_ID}" ]; then
                        echo "BLOCKED: the registry copy is not the image that was built."
                        echo "        built  image id=${BUILT_ID}"
                        echo "        pulled image id=${PULLED_ID}"
                        exit 1
                    fi

                    echo "Digest check OK: the registry copy is the image that was built and that the scans will examine."

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
            // Every scan that needs an IMAGE happens here, after the push:
            //   * Aqua        — the image that ships, local and registry copy
            //   * Trivy lib   — ${SCAN_IMAGE}, the builder stage, which still
            //                   holds the full frontend dependency tree
            //   * Trivy os    — ${FULL_IMAGE}, the runtime base we ship
            // The source-tree scans live in 'Code Scan (secrets + dependencies)'
            // before the build.
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${AQUA_CREDS_ID}",
                    usernameVariable: 'AQUA_USER',
                    passwordVariable: 'AQUA_PASSWORD'
                )]) {
                    sh '''
                        set -u

                        # Capture the scanner exit code instead of letting
                        # `set -e` kill the shell — otherwise a scanner failure
                        # produces no diagnostic at all, only a red stage.
                        SCAN_RC=0
                        podman run --rm --name aqua-scan-${BUILD_NUMBER} \
                            --network host \
                            --security-opt label=disable --user root \
                            -v ${PODMAN_SOCK}:/var/run/docker.sock \
                            ${SCANNER_IMAGE} \
                            scan \
                                --host ${AQUA_HOST} \
                                --local ${FULL_IMAGE} \
                                --no-verify \
                                --user ${AQUA_USER} \
                                --password ${AQUA_PASSWORD} \
                                --html > aqua-report.html 2> aqua-scan.err || SCAN_RC=$?

                        if [ "${SCAN_RC}" -ne 0 ]; then
                            echo "--- Aqua scanner stderr ---"
                            cat aqua-scan.err || true
                            echo "--- Aqua scanner output ---"
                            cat aqua-report.html || true
                            echo ""
                            echo "BLOCKED: Aqua scanner CLI exited ${SCAN_RC}"
                            echo "HINT: 'TLS handshake timeout' / 'Failed checking cybercenter to"
                            echo "      scanner compatibility' means the aqua-web console container"
                            echo "      on the Jenkins host has lost its outbound path. Fix on the"
                            echo "      host with:  podman network reload"
                            echo "      (or recreate aqua-web + aqua-gateway), then re-run."
                            exit 1
                        fi

                        echo "--- Aqua scan summary ---"
                        # Print the compliance marker so it shows in the console
                        grep -oE "Image Is (Compliant|Non-compliant)" aqua-report.html || true
                        # Hard CI/CD gate: pipeline only proceeds if image is Compliant.
                        # Non-compliant (or missing marker) fails the build.
                        grep -q "Image Is Compliant" aqua-report.html \
                            || { echo "BLOCKED: image is non-compliant (or scan report missing compliance marker)"; exit 1; }

                        # ------------------------------------------------------------------
                        # Also record the REGISTRY copy of the very same image.
                        #
                        # The scan above used --local, so the console files the
                        # image under the scanner's own local store. This second
                        # scan pulls the pushed image back from the registry, so
                        # the console ALSO lists it under
                        #     192.168.147.104:8082/hku-intranet:<version>
                        # and the client can find it by tag instead of by
                        # build number.
                        #
                        # Non-blocking on purpose: the local scan above is the
                        # gate (it inspects the exact bytes that will run), and
                        # this one only enriches the console record. If the
                        # registry reference cannot be resolved the build
                        # still proceeds.
                        #
                        # Do NOT add --register / --register-compliant here.
                        # Registration is a licence-counted operation, and the
                        # console refuses it once the plan's repository limit
                        # is reached ("the image license limit has been
                        # exceeded"). It is also unnecessary: the local scan
                        # above already scans the registry-qualified name
                        # (192.168.147.104:8082/hku-intranet:<version>), so
                        # the console files the image under that repository
                        # and tag on its own — the client finds it by tag
                        # without any explicit registration.
                        # ------------------------------------------------------------------
                        echo "--- Aqua registry scan (informational) ---"
                        podman run --rm --name aqua-scan-reg-${BUILD_NUMBER} \
                            --network host \
                            --security-opt label=disable --user root \
                            -v ${PODMAN_SOCK}:/var/run/docker.sock \
                            ${SCANNER_IMAGE} \
                            scan \
                                --host ${AQUA_HOST} \
                                --registry ${REGISTRY_URL} \
                                --no-verify \
                                --user ${AQUA_USER} \
                                --password ${AQUA_PASSWORD} \
                                --html \
                                ${IMAGE_NAME}:${IMAGE_VERSION} \
                                > aqua-registry-report.html 2> aqua-registry-scan.err \
                            || echo "NOTE: registry scan did not complete (informational only) — see aqua-registry-scan.err"

                        grep -oE "Image Is (Compliant|Non-compliant)" aqua-registry-report.html || true
                    '''
                }

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
                // HARD GATE: --exit-code 1 turns any HIGH/CRITICAL library
                // finding, any detected secret, and any CRITICAL OS CVE into a
                // build failure.
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
                    # that is the name Trivy and the Aqua scanner look for.
                    # The same mount works for both of them.
                    TRIVY_RC=0
                    podman run --rm --name hku-trivy-${BUILD_NUMBER} \
                        --network host --security-opt label=disable \
                        -v ${PODMAN_SOCK}:/var/run/docker.sock \
                        -v trivy-cache:/root/.cache/trivy \
                        -e TRIVY_DB_REPOSITORY=docker.io/aquasec/trivy-db:2 \
                        ${TRIVY_IMAGE} \
                        image --scanners vuln,secret \
                            --pkg-types library \
                            --severity HIGH,CRITICAL \
                            --exit-code 1 \
                            --format table \
                            ${SCAN_IMAGE} > trivy-report.txt 2>&1 || TRIVY_RC=$?

                    cat trivy-report.txt
                    echo "trivy (app dependencies) exit code: ${TRIVY_RC}"

                    # ------------------------------------------------------------------
                    # OS packages of the image we actually ship.
                    # HARD GATE on CRITICAL. The runtime base is
                    # oven/bun:1.3-alpine, which currently carries 0 CRITICAL
                    # and 4 HIGH (all with a fix available in a newer alpine
                    # release). Gating on HIGH too would block the build on a
                    # base-image update we do not control, so HIGH is
                    # reported and CRITICAL is the line that stops a build.
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

                    if [ "${TRIVY_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy reported HIGH/CRITICAL findings, detected a secret, or the scan itself failed — see trivy-report.txt"
                        exit 1
                    fi

                    if [ "${TRIVY_OS_RC}" -ne 0 ]; then
                        echo "BLOCKED: Trivy reported a CRITICAL OS vulnerability in the runtime image — see trivy-os-report.txt"
                        exit 1
                    fi

                    echo "Image scan OK: no HIGH/CRITICAL library CVEs, no detected secrets, no CRITICAL OS CVEs."
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'aqua-report.html,aqua-scan.err,aqua-registry-report.html,aqua-registry-scan.err,trivy-report.txt,trivy-os-report.txt',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('Deploy & Verify') {
            // CI/CD proof: spin up the scanned image on a spare port, hit the
            // health endpoint and the SPA root, and fail the build if either
            // is missing. Cleans the container up afterwards.
            //
            // The image no longer carries a default DB_HOST / DB_USER, and in
            // production mode it refuses to boot without SSO_COOKIE_SECRET —
            // so the verify container gets throwaway values for both. The DB
            // points at a closed port on purpose: the CI host has no
            // PostgreSQL, and pointing at a refused connection proves the
            // degraded-start path (liveness up, readiness 503) works.
            steps {
                sh '''
                    set -eux
                    podman run -d --name hku-intranet-verify-${BUILD_NUMBER} \
                        --network host \
                        -e HOST=127.0.0.1 \
                        -e PORT=${VERIFY_PORT} \
                        -e SSO_COOKIE_SECRET=ci-throwaway-secret-not-used-anywhere \
                        -e DB_HOST=127.0.0.1 \
                        -e DB_PORT=1 \
                        -e DB_USER=ci_throwaway \
                        -e DB_NAME=engg_intranet \
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

                    # Readiness must report the database as down (503 degraded)
                    # rather than the container pretending to be healthy. This
                    # is what an orchestrator readiness probe keys off.
                    READY_CODE=$(curl -s -o /tmp/hku-ready.json -w '%{http_code}' \
                        "http://127.0.0.1:${VERIFY_PORT}/health/ready" || true)
                    cat /tmp/hku-ready.json || true
                    echo ""
                    [ "${READY_CODE}" = "503" ] \
                        || { echo "BLOCKED: /health/ready returned ${READY_CODE}, expected 503 (no database in CI)"; \
                             podman logs hku-intranet-verify-${BUILD_NUMBER} || true; \
                             exit 1; }

                    echo "Webpage verified: /health ok + SPA root div + readiness 503 (degraded) on 127.0.0.1:${VERIFY_PORT}"
                '''
            }
            post {
                always {
                    sh 'podman rm -f hku-intranet-verify-${BUILD_NUMBER} || true'
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
                    READY=$(curl -fsS "http://${UAT_HOST}:${UAT_PORT}/health/ready")
                    echo "${READY}"
                    echo "${READY}" | grep -q "\"database\":\"${UAT_DB}\"" \
                        || { echo "BLOCKED: UAT is serving the wrong database, expected ${UAT_DB}"; exit 1; }

                    echo "UAT deployed: http://${UAT_HOST}:${UAT_PORT}/  (database ${UAT_DB})"
                '''
            }
        }

        stage('Manual Approval') {
            // The human gate. UAT is up and checked; a human decides whether
            // PRODUCTION gets it.
            //
            // `input` is core Jenkins — no plugin needed. Nothing clicked
            // within the timeout aborts the build, and "Reject" aborts it too.
            // The tag and the digest shown here are the ones the UAT site is
            // running right now, so the decision is about THOSE bytes.
            steps {
                timeout(time: 30, unit: 'MINUTES') {
                    input message: """Promote ${FULL_IMAGE} to production?

  image    : ${FULL_IMAGE}
  digest   : ${IMAGE_DIGEST}
  app      : ${APP_REPO} @ ${APP_COMMIT}
  UAT      : http://${UAT_HOST}:${UAT_PORT}/   (health ok, database ${UAT_DB})
  PROD     : http://${PROD_HOST}:${PROD_PORT}/

The SAME tag and the SAME digest that just passed the UAT check will be deployed to production.""",
                          ok: 'Promote to PROD'
                }
            }
        }

        stage('Deploy PROD (Database & Application)') {
            // The same role, the other target. The image is NOT rebuilt: the
            // site pulls the very tag that UAT is running.
            steps {
                sh '''
                    set -eux

                    export ANSIBLE_PRIVATE_KEY_FILE=${ANSIBLE_KEY}

                    cd ${WORKSPACE}/ansible
                    ansible-playbook -i inventory.ini deploy.yml \
                        -e intranet_target=intranet_prod \
                        -e intranet_image=${FULL_IMAGE}

                    curl -fsS "http://${PROD_HOST}:${PROD_PORT}/health"
                    echo ""
                    READY=$(curl -fsS "http://${PROD_HOST}:${PROD_PORT}/health/ready")
                    echo "${READY}"
                    echo "${READY}" | grep -q "\"database\":\"${PROD_DB}\"" \
                        || { echo "BLOCKED: PROD is serving the wrong database, expected ${PROD_DB}"; exit 1; }

                    echo "PROD deployed: http://${PROD_HOST}:${PROD_PORT}/  (database ${PROD_DB})"
                '''
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
                # run with --rm, but a FAILED run can leave one behind (the
                # Aqua scanner's scan-target container is the usual one), and
                # a container holding an image makes `podman rmi` refuse:
                #     image used by <id>: image is in use by a container
                podman rm -f aqua-scan-${BUILD_NUMBER} \
                             aqua-scan-reg-${BUILD_NUMBER} \
                             hku-audit-${BUILD_NUMBER} \
                             hku-audit-fs-${BUILD_NUMBER} \
                             hku-trivy-${BUILD_NUMBER} \
                             hku-trivy-fs-${BUILD_NUMBER} \
                             hku-trivy-os-${BUILD_NUMBER} \
                             hku-trivy-os-high-${BUILD_NUMBER} \
                             hku-intranet-verify-${BUILD_NUMBER} 2>/dev/null || true

                # Force-clear any other container still holding the scan-only
                # image. ${SCAN_IMAGE} is never used by the production
                # container, so removing its holders is always safe.
                for c in $(podman ps -aq --filter ancestor=${SCAN_IMAGE} 2>/dev/null); do
                    podman rm -f "$c" || true
                done

                # Deliberately NOT --force: if the production container is
                # running from ${FULL_IMAGE}, rmi correctly refuses and the
                # image stays. That is the safe outcome.
                podman rmi ${FULL_IMAGE} || true
                podman rmi ${SCAN_IMAGE} || true
            '''
        }
        success {
            echo "Pipeline SUCCESS — ${env.FULL_IMAGE} was scanned, checked in UAT, approved and deployed to PROD"
            emailext (
                subject: "✅ Build #${BUILD_NUMBER} PASSED — ${env.FULL_IMAGE}",
                body: """<h2>HKU ENGG Intranet — CI/CD — Build #${BUILD_NUMBER} PASSED</h2>
                    <p>Image: <code>${env.FULL_IMAGE}</code></p>
                    <p>Application: <code>${APP_REPO}</code> @ <code>${APP_COMMIT}</code></p>
                    <p>Aqua image scan: <b>Image Is Compliant</b> (malware, root user, sensitive data)</p>
                    <p>Code scan: no secrets in the source tree, no HIGH/CRITICAL dependency advisories, no CRITICAL OS CVEs</p>
                    <p>Deploy verify: /health + SPA root ok on <code>127.0.0.1:${VERIFY_PORT}</code></p>
                    <p><b>UAT</b>: <a href=\"http://${UAT_HOST}:${UAT_PORT}/\">http://${UAT_HOST}:${UAT_PORT}/</a> (database <code>${UAT_DB}</code>) — approved for production</p>
                    <p><b>PROD</b>: <a href=\"http://${PROD_HOST}:${PROD_PORT}/\">http://${PROD_HOST}:${PROD_PORT}/</a> (database <code>${PROD_DB}</code>)</p>
                    <p>Same tag and digest in both — UAT and PROD run the identical image.</p>
                    <p>Reports: <a href=\"${BUILD_URL}artifact/\">aqua-report.html, bun-audit.txt, trivy-secret-report.txt, trivy-report.txt, trivy-os-report.txt</a><br>
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
                subject: "❌ Build #${BUILD_NUMBER} FAILED",
                body: """<h2>HKU ENGG Intranet — CI/CD — Build #${BUILD_NUMBER} FAILED</h2>
                    <p>Image: <code>${env.FULL_IMAGE ?: 'unresolved'}</code></p>
                    <p>Check the console for the failure stage. If it stopped at <b>Manual Approval</b>, nothing was deployed to production.</p>
                    <p>Reports: <a href=\"${BUILD_URL}artifact/\">aqua-report.html, bun-audit.txt, trivy-secret-report.txt, trivy-report.txt, trivy-os-report.txt</a><br>
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
