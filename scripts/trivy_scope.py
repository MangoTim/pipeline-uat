#!/usr/bin/env python3
"""Sort Trivy's findings on the builder image into what SHIPS and what is
only a build tool.

The builder image is the only image that carries the frontend dependency
tree — the runtime image ships `dist/` and `server/node_modules`, but not
the frontend `node_modules`. So the builder image is scanned for library
CVEs, and it necessarily holds the whole tree: the packages that are
delivered AND the build tools that produce them.

`bun install` hoists, so the path of a finding does not say where the
package came from: picomatch is reached through vite, but it sits at
`app/node_modules/picomatch/package.json` all the same. The only reliable
answer is the dependency graph in the lockfiles, so this script uses the
same production closure as scripts/audit_scope.py:

  * a package that is in the production closure of either workspace SHIPS.
    An advisory on it is a real finding and blocks the build.
  * any other package is a build tool. The advisory is printed, with the
    path that reaches it, but it does not block.

The two workspaces are NOT the same, and the difference matters:

  frontend  only the compiled `dist/` bundle is delivered — the frontend
            node_modules are not in the runtime image at all. So the
            frontend ships its production closure and nothing else.

  server    the runtime image copies `server/` straight out of the builder,
            node_modules and devDependencies included. So the server ships
            its WHOLE installed tree. `--server-ship-dev` asks for that;
            the pipeline passes it, because the files really are in the
            image the customer receives.

Matching is by name AND version where the lockfile knows one. The two
workspaces can carry the same package at different versions (typescript
6.0.3 in the frontend build tree, 5.7.2 in the server tree), and only one
of the two may be the shipped copy.

Secrets are NOT scoped. A hardcoded credential is a finding wherever it
is, so a secret always blocks.

Usage:
    trivy_scope.py <trivy.json> <frontend.bun.lock> <server.bun.lock>
                   [--level high] [--server-ship-dev]

Exit codes:
    0   nothing that ships is vulnerable at or above --level, and no secret
    1   a SHIPPED package has an advisory at or above --level, or a secret
    2   the report could not be read — the gate refuses to pass
"""

import argparse
import json
import sys

from audit_scope import (SEVERITY_ORDER, closure, load_lockfile,
                         package_version, workspace_entry)


def load_report(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object found")
    return json.loads(text[start:])


def shipped_closure(lockfile, include_dev=False):
    """The packages one workspace delivers, and how they are reached.

    Returns (names, parents, versions): the set of package names that ship,
    the parent of each one (so the dependency path can be printed) and the
    resolved version of each one (so the right copy of a package can be
    told apart from a build-tool copy of the same name).
    """
    lock = load_lockfile(lockfile)
    packages = lock.get("packages") or {}
    workspace = workspace_entry(lock)

    roots = list((workspace.get("dependencies") or {}).keys())
    names, parents = closure(packages, roots)

    if include_dev:
        dev_roots = list((workspace.get("devDependencies") or {}).keys())
        dev_names, dev_parents = closure(packages, dev_roots)
        # The production path wins where both trees reach a package, and a
        # root of either tree stays a root — it has no parent.
        merged = dict(dev_parents)
        merged.update(parents)
        for root in set(roots) | set(dev_roots):
            merged.pop(root, None)
        parents = merged
        names = names | dev_names

    versions = {}
    for name in names:
        version = package_version(packages.get(name))
        if version:
            versions.setdefault(name, set()).add(version)
    return names, parents, versions


def is_shipped(name, version, versions):
    """Does this exact package reach the customer?"""
    if name not in versions:
        return False
    known = versions[name]
    if not known or version is None:
        # The lockfile does not pin a plain version for it, so the name is
        # all there is to go on.
        return True
    return version in known


def dependency_path(parents, target):
    chain = [target]
    current = target
    while current in parents:
        current = parents[current]
        chain.append(current)
    return " > ".join(reversed(chain))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("frontend_lock")
    parser.add_argument("server_lock")
    parser.add_argument("--level", default="high")
    parser.add_argument("--server-ship-dev", action="store_true",
                        help="the server's devDependencies ship too — the "
                             "runtime image copies server/node_modules out "
                             "of the builder")
    args = parser.parse_args()

    try:
        report = load_report(args.report)
    except Exception as exc:  # noqa: BLE001 - the message is the report
        print("could not read the Trivy report %s: %s" % (args.report, exc))
        print("the scan itself failed — the gate cannot pass")
        return 2

    try:
        frontend, frontend_parents, frontend_versions = shipped_closure(
            args.frontend_lock)
        server, server_parents, server_versions = shipped_closure(
            args.server_lock, include_dev=args.server_ship_dev)
    except Exception as exc:  # noqa: BLE001
        print("could not read the lockfiles: %s" % exc)
        print("the gate cannot pass")
        return 2

    shipped_names = frontend | server
    threshold = SEVERITY_ORDER.get(args.level.lower(), 2)

    shipped = []
    toolchain = []
    secrets = []

    for result in report.get("Results") or []:
        for secret in result.get("Secrets") or []:
            secrets.append({
                "title": secret.get("Title"),
                "severity": secret.get("Severity"),
                "target": result.get("Target"),
                "rule": secret.get("RuleID"),
            })
        for finding in result.get("Vulnerabilities") or []:
            severity = SEVERITY_ORDER.get(str(finding.get("Severity", "")).lower(), 0)
            if severity < threshold:
                continue
            package = finding.get("PkgName")
            version = finding.get("InstalledVersion")
            item = {
                "package": package,
                "severity": finding.get("Severity"),
                "reference": finding.get("VulnerabilityID"),
                "title": finding.get("Title"),
                "path": finding.get("PkgPath"),
                "installed": version,
                "fixed": finding.get("FixedVersion"),
            }
            if is_shipped(package, version, frontend_versions):
                item["via"] = dependency_path(frontend_parents, package)
                shipped.append(item)
            elif is_shipped(package, version, server_versions):
                item["via"] = dependency_path(server_parents, package)
                shipped.append(item)
            else:
                item["via"] = "a build tool (not in the production closure)"
                toolchain.append(item)

    print("=" * 72)
    print("Trivy findings on the builder image")
    print("report : %s" % args.report)
    print("level  : %s and above" % args.level)
    print("shipped packages : %d (frontend %d + server %d)"
          % (len(shipped_names), len(frontend), len(server)))
    print("=" * 72)

    if shipped:
        print("")
        print("SHIPPED — these packages are part of the delivered product:")
        for item in shipped:
            print("  %-16s %-9s %s" % (item["package"], item["severity"], item["reference"]))
            print("      %s" % item["title"])
            print("      via %s" % item["via"])
            print("      installed %s, fixed in %s" % (item["installed"], item["fixed"] or "(no fix)"))
    else:
        print("")
        print("SHIPPED — nothing at or above %s." % args.level)

    if toolchain:
        print("")
        print("BUILD-ONLY — these packages never reach the customer, so they do")
        print("not block the build. They are reported so they stay visible:")
        for item in toolchain:
            print("  %-16s %-9s %s" % (item["package"], item["severity"], item["reference"]))
            print("      %s" % item["title"])
            print("      %s" % item["path"])
            print("      via %s" % item["via"])
    else:
        print("")
        print("BUILD-ONLY — nothing at or above %s." % args.level)

    if secrets:
        print("")
        print("SECRETS — a hardcoded credential is a finding wherever it is:")
        for item in secrets:
            print("  %-9s %s  (%s)" % (item["severity"], item["title"], item["target"]))

    print("")
    if secrets:
        print("RESULT: BLOCKED — a secret was detected in the image.")
        return 1
    if shipped:
        print("RESULT: BLOCKED — a dependency that ships in this image has an advisory.")
        return 1
    print("RESULT: PASSED — nothing that ships is vulnerable at %s or above, and no secret was found." % args.level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
