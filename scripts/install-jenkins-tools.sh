#!/usr/bin/env bash
# Install the tools the pipeline-uat Jenkins job needs, INSIDE the Jenkins
# container on 192.168.147.104 — the CI host, which sits with UAT.
#
# The jenkins-with-podman image is a slim Debian image that ships neither
# python3 nor ansible. Both are needed:
#
#   ansible-playbook  — the deploy stages (Deploy UAT / Deploy PROD)
#   python3           — the Ansible controller on Debian
#
# It also checks that the SSH key the pipeline authenticates with is in
# place. The key belongs to the container, not to the host, so it has to be
# copied in whenever the container is recreated.
#
# The install is NOT baked into the image, so it is lost if the container is
# recreated. Re-run this script after any container recreate. It is
# idempotent — running it twice changes nothing.
#
# NOTE: the local git daemon that serves the OTHER pipeline's bare origin
# (mcp-dr-pipeline.git) is owned by the mcp-dr repository's own
# scripts/install-jenkins-tools.sh. This job checks out from GitHub, so it
# needs no git daemon.
#
# Usage (from the host, as the account that owns the container):
#
#   podman cp scripts/install-jenkins-tools.sh jenkins:/var/jenkins_home/
#   podman exec jenkins bash /var/jenkins_home/install-jenkins-tools.sh
#
# The SSH key — the pipeline uses it to reach .104 (UAT) and .105 (PROD):
#
#   podman cp ~/.ssh/id_rhai108_rsa jenkins:/var/jenkins_home/.ssh/
#   podman exec jenkins chmod 600 /var/jenkins_home/.ssh/id_rhai108_rsa
#
set -euo pipefail

SSH_KEY="${SSH_KEY:-/var/jenkins_home/.ssh/id_rhai108_rsa}"
REGISTRY="${REGISTRY:-192.168.147.104:8082}"

echo "=== before ==="
command -v ansible-playbook || echo "ansible-playbook: MISSING"
command -v python3 || echo "python3: MISSING"
[ -f "${SSH_KEY}" ] || echo "ssh key: MISSING (${SSH_KEY})"

export DEBIAN_FRONTEND=noninteractive

# The slim image ships no apt lists, and apt refuses to run without the
# partial/ directory in place.
mkdir -p /var/lib/apt/lists/partial /var/lib/apt/lists/auxfiles

apt-get update -qq
apt-get install -y --no-install-recommends \
    ansible \
    python3 \
    python3-pip \
    openssh-client \
    git \
    ca-certificates \
    gzip \
    rsync \
    curl

apt-get clean
rm -rf /var/lib/apt/lists/*

echo ""
echo "=== after ==="
python3 --version
ansible-playbook --version | head -1
ssh -V 2>&1
git --version

echo ""
echo "=== ssh key ==="
if [ -f "${SSH_KEY}" ]; then
    chmod 600 "${SSH_KEY}"
    ls -l "${SSH_KEY}"
else
    echo "MISSING — copy it in:"
    echo "  podman cp ~/.ssh/id_rhai108_rsa jenkins:${SSH_KEY}"
    echo "  podman exec jenkins chmod 600 ${SSH_KEY}"
fi

echo ""
echo "=== registry reachable? ==="
curl -fsS "http://${REGISTRY}/v2/_catalog" && echo "" || echo "WARNING: ${REGISTRY} did not answer"

echo ""
echo "OK — the Jenkins agent can run ansible-playbook."
