#!/usr/bin/env python3
"""Render ONE HTML page that shows every vulnerability the CI band found.

The CI band runs two scans, and they answer two different questions:

  the CODE scan   looks at the SOURCE: the hardcoded secrets in the files
                  and the dependency advisories the npm advisory registry
                  reports for the lockfiles.
  the IMAGE scan  looks at the IMAGES: the CVEs in the runtime base and in
                  the libraries of the builder stage, and the secrets baked
                  into the layers.

Trivy's own HTML template (/contrib/html.tpl in the image) renders ONE
Trivy report at a time, and the `bun audit` findings are not Trivy
findings at all. This script renders all of them together, in a single
page, so the customer gets one document that says what is in the image
AND what is in the code — instead of five text files to read side by
side. It is the open-source replacement for the console dashboard: the
same information, rendered by a script that runs in the build, with no
console to install, no account to create and no server to keep alive.

NOTHING HERE GATES THE BUILD. The gates are the scans themselves and the
two scope scripts (scripts/trivy_scope.py, scripts/audit_scope.py); this
script only presents their findings, and it says so on the page.

Producing the report IS a hard failure, though: a report that cannot be
read must never look like a clean scan. The same rule the scope scripts
follow — "not verified" must not look like "clean".

Usage:
    build_report.py --os-json FILE --image-json FILE --secret-json FILE
                    --audit FRONTEND.json SERVER.json
                    --lock FRONTEND.bun.lock SERVER.bun.lock
                    --out FILE [--image TEXT] [--tag TEXT] [--digest TEXT]
                    [--build TEXT] [--level high]

    --os-json       the runtime image's OS packages (Trivy, JSON)
    --image-json    the builder image's libraries and secrets (Trivy, JSON)
    --secret-json   the source tree's secrets (Trivy, JSON)
    --audit         the two `bun audit` outputs (frontend, server)
    --lock          the two lockfiles the scope is worked out from
    --out           the HTML file to write

Exit codes:
    0   the report was written
    2   an input could not be read — the report is not a pass
"""

import argparse
import html
import sys
from datetime import datetime, timezone

from audit_scope import (SEVERITY_ORDER, closure, load_audit, load_lockfile,
                         workspace_entry)
from trivy_scope import (dependency_path, is_shipped, load_report,
                         shipped_closure)

SEVERITY_COLOUR = {
    "CRITICAL": "#c62828",
    "HIGH": "#ef6c00",
    "MEDIUM": "#f9a825",
    "LOW": "#558b2f",
    "UNKNOWN": "#616161",
}


def esc(value):
    """One value, escaped for HTML."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def severity_rank(value):
    """The same scale the scope scripts use: low < moderate < high < critical.

    `bun audit` writes "moderate" where Trivy writes "medium"; both are the
    same position on the scale, and SEVERITY_ORDER knows both words.
    """
    return SEVERITY_ORDER.get(str(value or "unknown").lower(), 0)


def normalise_severity(value):
    """The severity as it is shown on the page."""
    text = str(value or "UNKNOWN").upper()
    return "MEDIUM" if text == "MODERATE" else text


def merge_parents(*mappings):
    """The dependency paths of several workspaces, in one dictionary."""
    merged = {}
    for mapping in mappings:
        merged.update(mapping)
    return merged


def advisory_identifier(advisory):
    """The name of an advisory, as a reader knows it.

    `bun audit` reports the npm advisory database's own numeric id, which
    means nothing to a reader. The GHSA identifier is in the URL, and that
    is the one people look the advisory up by.
    """
    url = advisory.get("url") or ""
    if "/advisories/" in url:
        return url.rsplit("/advisories/", 1)[-1]
    return advisory.get("id")


# --------------------------------------------------------------------------
# The findings, pulled out of the scan output
# --------------------------------------------------------------------------

def vulnerability_rows(report):
    """Every vulnerability in a Trivy report, as flat rows."""
    rows = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            rows.append({
                "package": vuln.get("PkgName"),
                "id": vuln.get("VulnerabilityID"),
                "severity": normalise_severity(vuln.get("Severity")),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion"),
                "title": vuln.get("Title"),
                "url": vuln.get("PrimaryURL"),
                "references": vuln.get("References") or [],
                "path": vuln.get("PkgPath"),
            })
    rows.sort(key=lambda row: (-severity_rank(row["severity"]),
                               str(row["package"]), str(row["id"])))
    return rows


def secret_rows(report):
    """Every secret in a Trivy report, as flat rows.

    The matched value itself is deliberately NOT carried over. Trivy masks
    it in most rules, but not in all of them, and this page goes to the
    customer — so the report says WHERE the secret is and what rule
    caught it, and never repeats the credential.
    """
    rows = []
    for result in report.get("Results") or []:
        for secret in result.get("Secrets") or []:
            start = secret.get("StartLine")
            rows.append({
                "rule": secret.get("RuleID"),
                "title": secret.get("Title"),
                "severity": normalise_severity(secret.get("Severity")),
                "target": result.get("Target"),
                "where": "%s:%s" % (result.get("Target"), start) if start
                         else result.get("Target"),
            })
    rows.sort(key=lambda row: (-severity_rank(row["severity"]),
                               str(row["target"]), str(row["rule"])))
    return rows


def audit_rows(audit, shipped_names, shipped_parents, build_names, build_parents):
    """Every `bun audit` advisory, with the scope worked out from the lockfile.

    The same rule the two scope scripts apply: a package in the production
    closure SHIPS, anything else is a build tool. An advisory on a build
    tool is reported — with the path that reaches it — and does not block.
    """
    rows = []
    for package, advisories in sorted(audit.items()):
        for advisory in advisories or []:
            ships = package in shipped_names
            if ships:
                via = dependency_path(shipped_parents, package)
            elif package in build_names:
                via = dependency_path(build_parents, package)
            else:
                via = ("(not reachable from the build tools either — an orphan "
                       "in the lockfile)")
            rows.append({
                "package": package,
                "id": advisory_identifier(advisory),
                "url": advisory.get("url"),
                "severity": normalise_severity(advisory.get("severity")),
                "title": advisory.get("title"),
                "vulnerable": advisory.get("vulnerable_versions"),
                "ships": ships,
                "via": via,
            })
    rows.sort(key=lambda row: (-severity_rank(row["severity"]),
                               str(row["package"])))
    return rows


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

CSS = """
* { font-family: -apple-system, Segoe UI, Arial, Helvetica, sans-serif; }
body { margin: 0 auto; padding: 32px; max-width: 1400px; color: #1c1c1c;
       background: #fafafa; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 34px 0 6px; padding-bottom: 6px;
     border-bottom: 2px solid #d5d5d5; }
p.note { margin: 6px 0 12px; color: #555; font-size: 13.5px; max-width: 1000px; }
table { border-collapse: collapse; background: #fff; font-size: 13px;
        box-shadow: 0 1px 2px rgba(0,0,0,.08); }
th, td { border: 1px solid #dcdcdc; padding: 6px 9px; text-align: left;
         vertical-align: top; }
th { background: #f0f0f0; font-weight: 600; }
td.num, th.num { text-align: right; }
tr:nth-child(even) td { background: #fbfbfb; }
.meta td:first-child { color: #666; width: 190px; }
.sev { color: #fff; font-weight: 600; text-align: center;
       border-radius: 3px; padding: 1px 7px; white-space: nowrap; }
.badge { display: inline-block; font-size: 11.5px; font-weight: 600;
         border-radius: 3px; padding: 1px 7px; white-space: nowrap; }
.badge.ships { background: #c62828; color: #fff; }
.badge.tool  { background: #e0e0e0; color: #333; }
.badge.gate  { background: #c62828; color: #fff; }
.badge.rep   { background: #e0e0e0; color: #333; }
.badge.clean { background: #2e7d32; color: #fff; }
.badge.block { background: #c62828; color: #fff; }
.empty { padding: 10px 12px; color: #2e7d32; font-weight: 600; }
.count { font-weight: 600; }
a { color: #1565c0; }
code { background: #f0f0f0; padding: 1px 5px; border-radius: 3px;
       font-size: 12.5px; }
footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid #d5d5d5;
         color: #666; font-size: 12.5px; }
"""


def severity_cell(severity):
    text = normalise_severity(severity)
    colour = SEVERITY_COLOUR.get(text, "#616161")
    return '<span class="sev" style="background:%s">%s</span>' % (colour, esc(text))


def links_cell(row, limit=3):
    """The advisory's own page, plus a few of the references."""
    parts = []
    if row.get("url"):
        parts.append('<a href="%s">advisory</a>' % esc(row["url"]))
    for reference in row.get("references") or []:
        if len(parts) >= limit + 1:
            break
        parts.append('<a href="%s">ref</a>' % esc(reference))
    if not parts:
        return "—"
    return " ".join(parts)


def render_table(headers, rows):
    """A table, or the one-line "nothing found" when there are no rows."""
    if not rows:
        return '<div class="empty">Nothing found — no findings of this kind.</div>'
    head = "".join("<th>%s</th>" % esc(header) for header in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join("<td>%s</td>" % cell for cell in row) + "</tr>")
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (
        head, "".join(body))


def counts_of(rows):
    counts = {}
    for row in rows:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1
    return counts


def summary_rows(sections):
    """One line per scan: how many of each severity, and the verdict."""
    for section in sections:
        counts = counts_of(section["rows"])
        cells = "".join('<td class="num count">%d</td>' % counts.get(level, 0)
                        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        total = sum(counts.get(level, 0)
                    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        yield ("<td><b>%s</b></td>%s<td class=\"num count\">%d</td>"
               "<td><span class=\"badge %s\">%s</span></td>"
               % (esc(section["name"]), cells, total,
                  section["verdict_class"], esc(section["verdict"])))


def build_page(args, sections):
    """The whole document."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    meta_rows = [
        ("Image", args.image or "—"),
        ("Tag", args.tag or "—"),
        ("Digest", args.digest or "—"),
        ("Build", args.build or "—"),
        ("Generated", now),
        ("Scanner", "Trivy (Apache-2.0) + bun audit — open source only"),
    ]
    meta = "".join("<tr><td>%s</td><td><code>%s</code></td></tr>"
                   % (esc(key), esc(value)) for key, value in meta_rows)

    summary = "".join("<tr>%s</tr>" % row for row in summary_rows(sections))
    body = "".join(section["html"] for section in sections)

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HKU ENGG Intranet — vulnerability report — %s</title>
<style>%s</style>
</head>
<body>
<h1>HKU ENGG Intranet — vulnerability report</h1>
<p class="note">Every vulnerability and every secret the CI band found in this
build: the source tree and the lockfiles (the code scan), and the images that
were built and pushed (the image scan). The image was scanned before it was
deployed, and it is the same image — the same digest — that UAT and production
run.</p>
<table class="meta">%s</table>

<h2>Summary</h2>
<table><thead><tr><th>Scan</th><th class="num">CRITICAL</th><th class="num">HIGH</th>
<th class="num">MEDIUM</th><th class="num">LOW</th><th class="num">Total</th>
<th>Verdict</th></tr></thead><tbody>%s</tbody></table>

%s

<footer>
<p>Generated by <code>scripts/build_report.py</code> from the CI band's own scan
output. The gates are the scans themselves and the two scope scripts
(<code>trivy_scope.py</code>, <code>audit_scope.py</code>) — this page presents
their findings, it does not decide anything.</p>
<p><b>Not covered by this report:</b> malware. The Trivy malware plugin has been
withdrawn upstream, so there is no open-source malware scan in this pipeline
today. If malware scanning is required it needs a separate scanner (for example
ClamAV) with its own signature database to maintain.</p>
</footer>
</body>
</html>
""" % (esc(args.tag or args.image or "build"), CSS, meta, summary, body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-json", required=True)
    parser.add_argument("--image-json", required=True)
    parser.add_argument("--secret-json", required=True)
    parser.add_argument("--audit", nargs=2, required=True,
                        metavar=("FRONTEND", "SERVER"))
    parser.add_argument("--lock", nargs=2, required=True,
                        metavar=("FRONTEND", "SERVER"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--tag", default="")
    parser.add_argument("--digest", default="")
    parser.add_argument("--build", default="")
    parser.add_argument("--level", default="high")
    args = parser.parse_args()

    # ---- the inputs -------------------------------------------------------
    try:
        os_report = load_report(args.os_json)
        image_report = load_report(args.image_json)
        secret_report = load_report(args.secret_json)
        audit_frontend = load_audit(args.audit[0])
        audit_server = load_audit(args.audit[1])
        frontend_lock = load_lockfile(args.lock[0])
        server_lock = load_lockfile(args.lock[1])
    except Exception as exc:  # noqa: BLE001 - the message is the report
        print("could not read the scan output: %s" % exc)
        print("the report cannot be written — an unreadable report must not "
              "look like a clean scan")
        return 2

    threshold = SEVERITY_ORDER.get(args.level.lower(), 2)

    # ---- the scope, worked out from the lockfiles -------------------------
    # The frontend ships only its production closure (the compiled bundle is
    # delivered, the frontend node_modules are not in the runtime image). The
    # server ships its WHOLE installed tree, because the runtime image copies
    # server/ — node_modules and all — out of the builder.
    def workspace_scope(lock, include_dev):
        packages = lock.get("packages") or {}
        workspace = workspace_entry(lock)
        roots = list((workspace.get("dependencies") or {}).keys())
        shipped, parents = closure(packages, roots)
        dev_roots = list((workspace.get("devDependencies") or {}).keys())
        build, build_parents = closure(packages, dev_roots)
        if include_dev:
            shipped = shipped | build
            parents = merge_parents(build_parents, parents)
        return shipped, parents, build, build_parents

    fe_shipped, fe_parents, fe_build, fe_build_parents = workspace_scope(
        frontend_lock, include_dev=False)
    sv_shipped, sv_parents, sv_build, sv_build_parents = workspace_scope(
        server_lock, include_dev=True)

    # ---- the image's libraries, scoped by the same rule -------------------
    image_libs = vulnerability_rows(image_report)
    try:
        fe_names, fe_paths, fe_versions = shipped_closure(args.lock[0])
        sv_names, sv_paths, sv_versions = shipped_closure(args.lock[1],
                                                            include_dev=True)
    except Exception as exc:  # noqa: BLE001
        print("could not read the lockfiles: %s" % exc)
        return 2

    for row in image_libs:
        if is_shipped(row["package"], row.get("installed"), fe_versions):
            row["scope"] = "ships"
            row["via"] = dependency_path(fe_paths, row["package"])
        elif is_shipped(row["package"], row.get("installed"), sv_versions):
            row["scope"] = "ships"
            row["via"] = dependency_path(sv_paths, row["package"])
        else:
            row["scope"] = "tool"
            row["via"] = "a build tool — not in the production closure"

    # ---- the sections -----------------------------------------------------
    sections = []

    os_rows = vulnerability_rows(os_report)
    os_critical = [row for row in os_rows if row["severity"] == "CRITICAL"]
    os_high = [row for row in os_rows if row["severity"] == "HIGH"]
    os_rows_html = render_table(
        ["Package", "Vulnerability", "Severity", "Installed", "Fixed", "Gate",
         "Title", "Links"],
        [[esc(row["package"]),
          '<a href="%s">%s</a>' % (esc(row["url"]), esc(row["id"]))
          if row.get("url") else esc(row["id"]),
          severity_cell(row["severity"]),
          esc(row["installed"]),
          esc(row["fixed"]) or "—",
          '<span class="badge gate">blocks</span>' if row["severity"] == "CRITICAL"
          else '<span class="badge rep">reported</span>',
          esc(row["title"]),
          links_cell(row)] for row in os_rows])
    sections.append({
        "name": "Image — OS packages",
        "rows": os_rows,
        "verdict": ("BLOCKED — a CRITICAL CVE is in the runtime image"
                    if os_critical else
                    ("no CRITICAL; %d HIGH reported and accepted" % len(os_high)
                     if os_high else "clean")),
        "verdict_class": "block" if os_critical else ("rep" if os_high else "clean"),
        "html": """<h2>1. Image — OS packages of the runtime base</h2>
<p class="note">The runtime image is what the customer runs. Its OS packages
come from the base image and are inherited from it, not from this code. A
CRITICAL finding here stops the build; a HIGH finding is reported and
accepted, with the reason recorded in the pipeline's own notes.</p>
%s""" % os_rows_html,
    })

    lib_rows_html = render_table(
        ["Package", "Vulnerability", "Severity", "Installed", "Fixed", "Ships?",
         "Reached via", "Title", "Links"],
        [[esc(row["package"]),
          '<a href="%s">%s</a>' % (esc(row["url"]), esc(row["id"]))
          if row.get("url") else esc(row["id"]),
          severity_cell(row["severity"]),
          esc(row["installed"]),
          esc(row["fixed"]) or "—",
          '<span class="badge ships">ships</span>' if row["scope"] == "ships"
          else '<span class="badge tool">build tool</span>',
          esc(row["via"]),
          esc(row["title"]),
          links_cell(row)] for row in image_libs])
    lib_shipped_bad = [row for row in image_libs
                       if row["scope"] == "ships"
                       and severity_rank(row["severity"]) >= threshold]
    sections.append({
        "name": "Image — libraries",
        "rows": image_libs,
        "verdict": ("BLOCKED — a dependency that ships has an advisory"
                    if lib_shipped_bad
                    else "clean — nothing that ships is vulnerable"),
        "verdict_class": "block" if lib_shipped_bad else "clean",
        "html": """<h2>2. Image — library dependencies</h2>
<p class="note">The builder stage still holds the whole frontend dependency
tree, so this is where the frontend libraries are scanned. A finding on a
package that <b>ships</b> is a real finding and stops the build; a finding on
a build tool is reported with the path that reaches it, and does not — it
never reaches the customer.</p>
%s""" % lib_rows_html,
    })

    image_secrets = secret_rows(image_report)
    sections.append({
        "name": "Image — secrets",
        "rows": image_secrets,
        "verdict": ("BLOCKED — a secret is baked into the image"
                    if image_secrets else "clean — no secret in the image"),
        "verdict_class": "block" if image_secrets else "clean",
        "html": """<h2>3. Image — secrets in the layers</h2>
<p class="note">A hardcoded credential is a finding wherever it is, so a secret
in the image blocks the build. The matched value is not reproduced here — only
where it is and which rule caught it.</p>
%s""" % render_table(
            ["Rule", "Severity", "Where", "Title"],
            [[esc(row["rule"]), severity_cell(row["severity"]),
              esc(row["where"]), esc(row["title"])] for row in image_secrets]),
    })

    source_secrets = secret_rows(secret_report)
    sections.append({
        "name": "Code — secrets in the source",
        "rows": source_secrets,
        "verdict": ("BLOCKED — a secret is in the source tree"
                    if source_secrets else "clean — no secret in the source tree"),
        "verdict_class": "block" if source_secrets else "clean",
        "html": """<h2>4. Code scan — secrets in the source tree</h2>
<p class="note">Scanned before the build, on the working tree, so a hardcoded
secret is caught before it is baked into a layer and pushed to the registry.
The matched value is not reproduced here — only where it is and which rule
caught it.</p>
%s""" % render_table(
            ["Rule", "Severity", "Where", "Title"],
            [[esc(row["rule"]), severity_cell(row["severity"]),
              esc(row["where"]), esc(row["title"])] for row in source_secrets]),
    })

    deps = (audit_rows(audit_frontend, fe_shipped, fe_parents,
                        fe_build, fe_build_parents)
            + audit_rows(audit_server, sv_shipped, sv_parents,
                         sv_build, sv_build_parents))
    deps.sort(key=lambda row: (-severity_rank(row["severity"]), str(row["package"])))
    deps_html = render_table(
        ["Package", "Advisory", "Severity", "Vulnerable versions", "Ships?",
         "Reached via", "Title", "Link"],
        [[esc(row["package"]),
          esc(row["id"]),
          severity_cell(row["severity"]),
          esc(row["vulnerable"]),
          '<span class="badge ships">ships</span>' if row["ships"]
          else '<span class="badge tool">build tool</span>',
          esc(row["via"]),
          esc(row["title"]),
          '<a href="%s">advisory</a>' % esc(row["url"]) if row.get("url") else "—"]
         for row in deps])
    deps_bad = [row for row in deps
                if row["ships"] and severity_rank(row["severity"]) >= threshold]
    sections.append({
        "name": "Code — dependency advisories",
        "rows": deps,
        "verdict": ("BLOCKED — a dependency that ships has an advisory"
                    if deps_bad else "clean — nothing that ships is vulnerable"),
        "verdict_class": "block" if deps_bad else "clean",
        "html": """<h2>5. Code scan — dependency advisories</h2>
<p class="note">Straight from the npm advisory registry, through the two
lockfiles. The frontend ships only its production closure — the compiled
bundle is delivered, the frontend node_modules are not in the runtime image.
The server ships its whole installed tree, because the runtime image copies
<code>server/</code> out of the builder. An advisory on a package that
<b>ships</b> stops the build; an advisory on a build tool is reported with the
path that reaches it, and does not.</p>
%s""" % deps_html,
    })

    page = build_page(args, sections)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(page)

    print("vulnerability report written: %s (%d bytes)" % (args.out, len(page)))
    for section in sections:
        print("  %-34s %s" % (section["name"], section["verdict"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
