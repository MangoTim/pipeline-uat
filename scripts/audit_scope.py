#!/usr/bin/env python3
"""Split `bun audit` findings into what SHIPS and what is only a build tool.

`bun audit` reads the LOCKFILE, and a lockfile holds the whole dependency
tree — the packages that are delivered AND the packages that only exist to
build them. It has no flag to tell the two apart, so a vulnerability in a
build tool is reported exactly like a vulnerability in the delivered
product.

That matters here: `picomatch` is reached only through `vite`, a build
tool, and its latest release is the vulnerable one — there is no fix to
install. A gate that blocks on it blocks every build forever without ever
making the product any safer.

So this script works out the PRODUCTION dependency closure of the
workspace from bun.lock — the packages reachable from `dependencies` — and
then sorts every advisory into one of two buckets:

  SHIPPED     the package is in the production closure. It is part of the
              delivered product, so an advisory on it is a real finding
              and it BLOCKS the build.

  BUILD-ONLY  the package is not in the production closure. It never
              reaches the customer, so the advisory is reported — with the
              path that reaches it — but does not block.

Usage:
    audit_scope.py <bun.lock> <audit.json> [--level high] [--label NAME]
                  [--ship-dev]

    --ship-dev  treat the workspace's devDependencies as shipped too. The
                server needs it: the runtime image copies `server/` — and
                therefore `server/node_modules`, dev dependencies included —
                straight out of the builder, so those files DO reach the
                customer. The frontend must NOT use it: only the compiled
                `dist/` bundle is shipped, never the frontend node_modules.

Exit codes:
    0   nothing shipped is vulnerable at or above --level
    1   a SHIPPED package has an advisory at or above --level
    2   the lockfile or the audit output could not be read — the gate
        refuses to pass, because "not verified" must not look like "clean"
"""

import argparse
import json
import re
import sys
from collections import deque

# `bun audit` reports "moderate"; npm uses "medium". Both map to the
# same position in the order below.
SEVERITY_ORDER = {
    "low": 0,
    "moderate": 1,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

# A resolved version looks like 5.7.2. A URL dependency (xlsx is installed
# from a tarball URL) has no version at all, and its lockfile entry ends in
# the URL — that is not a version and must not be matched as one.
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")


def package_version(entry):
    """The resolved version of a lockfile entry, or None when there is none."""
    if not entry or not isinstance(entry[0], str):
        return None
    candidate = entry[0].rsplit("@", 1)[-1]
    return candidate if _VERSION_RE.match(candidate) else None


def load_lockfile(path):
    """bun.lock is JSONC: JSON with trailing commas allowed."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def load_audit(path):
    """The audit file is JSON, but a stray banner line in front of it must
    not break the parse — the first '{' starts the object."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object found")
    return json.loads(text[start:])


def workspace_entry(lock):
    """The workspace a lockfile belongs to: its dependencies and its
    devDependencies."""
    workspaces = lock.get("workspaces") or {}
    if "" in workspaces:
        return workspaces[""]
    for entry in workspaces.values():
        if isinstance(entry, dict) and ("dependencies" in entry or "devDependencies" in entry):
            return entry
    return {}


def package_edges(packages, name):
    """The packages one package depends on. peerDependencies are left out:
    they are not installed on their own, and the optional ones are exactly
    the ones that must not drag a package into a closure."""
    entry = packages.get(name)
    if not entry:
        return []
    meta = entry[2] if len(entry) > 2 and isinstance(entry[2], dict) else {}
    edges = []
    for key in ("dependencies", "optionalDependencies"):
        edges.extend((meta.get(key) or {}).keys())
    return edges


def closure(packages, roots):
    """Every package reachable from `roots`, and the parent of each one —
    the parent is what makes the dependency path printable."""
    seen = set()
    parents = {}
    queue = deque(roots)
    while queue:
        name = queue.popleft()
        if name in seen:
            continue
        seen.add(name)
        for dependency in package_edges(packages, name):
            if dependency not in seen:
                parents.setdefault(dependency, name)
                queue.append(dependency)
    return seen, parents


def dependency_path(parents, target):
    """The chain from a root package down to `target`, as text."""
    chain = [target]
    current = target
    while current in parents:
        current = parents[current]
        chain.append(current)
    return " > ".join(reversed(chain))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile")
    parser.add_argument("audit")
    parser.add_argument("--level", default="high")
    parser.add_argument("--label", default="this workspace")
    parser.add_argument("--ship-dev", action="store_true",
                        help="the devDependencies ship too (the server's "
                             "node_modules is copied into the runtime image)")
    args = parser.parse_args()

    try:
        lock = load_lockfile(args.lockfile)
    except Exception as exc:  # noqa: BLE001 - the message is the report
        print("could not read the lockfile %s: %s" % (args.lockfile, exc))
        return 2

    try:
        audit = load_audit(args.audit)
    except Exception as exc:  # noqa: BLE001
        print("could not read the audit output %s: %s" % (args.audit, exc))
        print("the npm advisory registry may be unreachable — the gate cannot pass")
        return 2

    packages = lock.get("packages") or {}
    workspace = workspace_entry(lock)
    production_roots = list((workspace.get("dependencies") or {}).keys())
    build_roots = list((workspace.get("devDependencies") or {}).keys())

    production, production_parents = closure(packages, production_roots)
    build_only, build_parents = closure(packages, build_roots)

    # What actually reaches the customer. The frontend ships only its
    # production closure (the compiled bundle). The server ships its WHOLE
    # installed tree, because the runtime image copies `server/` — node_modules
    # and all — out of the builder.
    if args.ship_dev:
        shipped_set = production | build_only
        shipped_parents = dict(build_parents)
        shipped_parents.update(production_parents)
    else:
        shipped_set = production
        shipped_parents = production_parents

    threshold = SEVERITY_ORDER.get(args.level.lower(), 2)

    shipped = []
    toolchain = []
    for package, advisories in sorted(audit.items()):
        for advisory in advisories:
            severity = SEVERITY_ORDER.get(str(advisory.get("severity", "")).lower(), 0)
            if severity < threshold:
                continue
            finding = {
                "package": package,
                "severity": str(advisory.get("severity", "unknown")),
                "reference": advisory.get("url") or advisory.get("id"),
                "title": advisory.get("title"),
                "vulnerable_versions": advisory.get("vulnerable_versions"),
            }
            if package in shipped_set:
                finding["path"] = dependency_path(shipped_parents, package)
                shipped.append(finding)
            else:
                finding["path"] = (
                    dependency_path(build_parents, package)
                    if package in build_only
                    else "(not reachable from the build tools either — an orphan in the lockfile)"
                )
                toolchain.append(finding)

    print("=" * 72)
    print("Dependency advisories — %s" % args.label)
    print("lockfile : %s" % args.lockfile)
    print("level    : %s and above" % args.level)
    print("shipped packages : %d%s" % (
        len(shipped_set),
        " (production + development — the whole tree ships)" if args.ship_dev else "",
    ))
    print("=" * 72)

    if shipped:
        print("")
        print("SHIPPED — these packages are part of the delivered product:")
        for finding in shipped:
            print("  %-18s %-9s %s" % (finding["package"], finding["severity"], finding["reference"]))
            print("      %s" % finding["title"])
            print("      via %s" % finding["path"])
            print("      vulnerable versions: %s" % finding["vulnerable_versions"])
    else:
        print("")
        print("SHIPPED — nothing at or above %s." % args.level)

    if toolchain:
        print("")
        print("BUILD-ONLY — these packages never reach the customer, so they do")
        print("not block the build. They are reported so they stay visible:")
        for finding in toolchain:
            print("  %-18s %-9s %s" % (finding["package"], finding["severity"], finding["reference"]))
            print("      %s" % finding["title"])
            print("      via %s" % finding["path"])
    else:
        print("")
        print("BUILD-ONLY — nothing at or above %s." % args.level)

    print("")
    if shipped:
        print("RESULT: BLOCKED — a dependency that ships in this image has an advisory.")
        return 1
    print("RESULT: PASSED — nothing that ships is vulnerable at %s or above." % args.level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
