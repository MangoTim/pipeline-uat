"""Render the CI/CD design as one PNG — GitHub, Jenkins, UAT, PROD.

    python docs/diagrams/pipeline/build_design.py

Writes, next to this script:

    diagram-design.html                the source (this is what you edit)
    Pipeline-Design-UAT-PROD.png      the slide

The picture follows the composition of a Red Hat reference diagram: the SCM
at the far left, a CD band across the top holding the environments, and a CI
band underneath holding the build. Boxes carry a title and nothing else —
the detail lives in the README, not on the slide.

It is the shape the HKU ENGG Intranet pipeline uses: GitHub is the SCM,
Jenkins builds and scans the image once, the registry holds it, UAT gets it
first, and a human approves before it goes to production.

The pipeline is TWO Jenkins jobs. `pipeline-uat` builds, scans and deploys
UAT; `pipeline-prod` approves and deploys production. The picture says so,
because the gate is a job boundary and not a step inside one build.

    python docs/diagrams/pipeline/build_design.py          # render everything
    python docs/diagrams/pipeline/build_design.py --html   # HTML only
"""

from __future__ import annotations

import sys
from pathlib import Path
from string import Template

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_diagrams import render  # noqa: E402

HERE = Path(__file__).resolve().parent

PALETTE = dict(
    ink="#1A1A1A",
    grey="#555555",
    line="#C9C9C9",
    blue="#0B3D91",
    blueband="#DEE8F7",
    blueedge="#9DB8DC",
    red="#B30000",
    redband="#FBE3E3",
    rededge="#E39A9A",
    green="#1B6B3A",
    greenbg="#E9F5EE",
    amber="#8A4A00",
    redbg="#FBECEC",
    infobg="#EAF1F8",
    yellow="#FFF3CD",
    yellowedge="#C9A227",
    yellowink="#7A5A00",
    github="#24292F",
    postgres="#336791",
)

CSS = Template("""
  :root {
    --ink: $ink; --grey: $grey; --line: $line;
    --blue: $blue; --blueband: $blueband; --blueedge: $blueedge;
    --red: $red; --redband: $redband; --rededge: $rededge;
    --green: $green; --amber: $amber;
    --greenbg: $greenbg; --redbg: $redbg; --infobg: $infobg;
    --yellow: $yellow; --yellowedge: $yellowedge; --yellowink: $yellowink;
    --github: $github; --postgres: $postgres;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; background: #FFFFFF; color: var(--ink);
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .sheet { padding: 24px 24px 18px; width: 1450px; }
  .rule { height: 5px; background: var(--blue); border-radius: 3px; margin: 0 0 16px 0; }

  /* ================= the canvas ================= */
  .canvas { position: relative; display: flex; gap: 56px; align-items: stretch; }
  .leftcol {
    position: relative; flex: 0 0 176px; display: flex; flex-direction: column;
  }
  .rightcol { flex: 1 1 auto; display: flex; flex-direction: column; gap: 40px; }

  /* ---- the numbered callout circles ---- */
  .callout {
    position: absolute; width: 29px; height: 29px; border-radius: 50%;
    background: var(--yellow); border: 1.5px solid var(--yellowedge);
    color: var(--yellowink); font-size: 14px; font-weight: 700;
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 1px 3px rgba(0,0,0,.14); z-index: 9;
  }
  .callout.plain { position: static; box-shadow: none; }

  /* ================= the SCM box, far left ================= */
  .legend2 { position: relative; z-index: 2; padding: 1px 0 0 26px; margin-top: 40px; }
  .legend2 .txt { font-size: 11px; color: var(--ink); line-height: 1.45; }
  .legend2 .txt b { display: block; font-size: 11.5px; }

  /* ---- the dashed path: up out of the GitHub server, into the CD band ---- */
  .hookh { position: absolute; right: 100%; top: 24px; width: 273px;
           border-top: 1.4px dashed #8A8A8A; }
  .hookh::after {
    content: ""; position: absolute; right: -1px; top: -4.5px;
    border-left: 8px solid #8A8A8A; border-top: 4.5px solid transparent;
    border-bottom: 4.5px solid transparent;
  }

  .gitbox {
    position: relative; z-index: 2; margin-top: auto; background: #FFFFFF;
    border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px 10px 11px;
    box-shadow: 0 1px 3px rgba(0,0,0,.07);
  }
  /* the vertical run of the dashed path, straight up out of the box */
  .gitbox::before { content: ""; position: absolute; left: 18px; bottom: 100%;
                    height: 281px; border-left: 1.4px dashed #8A8A8A; }
  .gitbox .wordmark {
    display: flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 700;
    color: var(--github);
  }
  .gitbox .wordmark i {
    font-style: normal; background: var(--github); color: #FFFFFF; border-radius: 4px;
    font-size: 10px; padding: 2px 6px; letter-spacing: .5px;
  }
  .gitbox .sub { font-size: 10.5px; color: var(--ink); margin: 4px 0 0 0; line-height: 1.35; }

  /* ---- the arrow from the SCM into the CI band ---- */
  .conn { position: absolute; left: 100%; top: 50%; width: 56px; height: 20px;
          transform: translateY(-50%); }
  .conn .line { position: absolute; left: 0; right: 7px; top: 9px;
                border-top: 1.6px solid var(--ink); }
  .conn .line::after {
    content: ""; position: absolute; right: -1px; top: -4.5px;
    border-left: 8px solid var(--ink); border-top: 4.5px solid transparent;
    border-bottom: 4.5px solid transparent;
  }
  .conn .num {
    position: absolute; left: 13px; top: -21px; width: 29px; height: 29px;
    border-radius: 50%; background: var(--yellow); border: 1.5px solid var(--yellowedge);
    color: var(--yellowink); font-size: 14px; font-weight: 700;
    display: flex; align-items: center; justify-content: center;
  }

  /* ================= the bands ================= */
  .band { position: relative; border: 1.5px solid; border-radius: 3px; }
  .band.cd { background: var(--redband); border-color: var(--rededge); }
  .band.ci { background: var(--blueband); border-color: var(--blueedge);
             align-self: flex-start; width: 620px; }
  .band-h {
    display: flex; align-items: center; justify-content: space-between;
    font-size: 12.5px; font-weight: 700; letter-spacing: .8px; padding: 7px 12px 0 12px;
  }
  .band.cd .band-h { color: var(--red); }
  .band.ci .band-h { color: var(--blue); }
  /* the host a band runs on, next to the band title */
  .band-title { display: flex; align-items: center; gap: 9px; }
  .hostpill { font-size: 10px; font-weight: 700; letter-spacing: .1px;
              font-family: Consolas, "DejaVu Sans Mono", monospace;
              color: inherit; background: #FFFFFF; border: 1px solid currentColor;
              border-radius: 4px; padding: 2px 7px; }
  .brands { display: flex; gap: 8px; }
  .brand { font-size: 11px; font-weight: 800; letter-spacing: .6px; color: #FFFFFF;
           border-radius: 4px; padding: 3px 9px; }
  .brand.github { background: var(--github); }
  .brand.ansible { background: #111111; }
  .brand.podman { background: var(--blue); }
  .brand.aqua { background: #1F6FEB; }
  .brand.trivy { background: #5A3E8B; }
  .band-b { padding: 8px 12px 12px 12px; }
  /* the one line of honest detail under a band */
  .band-note { font-size: 9.5px; color: var(--grey); margin-top: 8px; line-height: 1.35; }

  /* ================= the environments ================= */
  .env-row { position: relative; display: flex; gap: 10px; align-items: stretch;
             padding-top: 50px; }
  .env { position: relative; background: #FFFFFF; border: 1.5px dashed #8A8A8A;
         border-radius: 4px; padding: 30px 10px 10px 10px;
         display: flex; flex-direction: column; }
  .env.uat { flex: 1 1 300px; margin-left: 44px; }
  .env.prod { flex: 1 1 300px; }
  .env-t { position: absolute; left: 10px; top: 8px; font-size: 11.5px; font-weight: 700; }
  /* the host each environment actually runs on, inline with the title */
  .env-host { display: inline-block; font-size: 9.5px; font-weight: 700; letter-spacing: .1px;
              font-family: Consolas, "DejaVu Sans Mono", monospace; color: #FFFFFF;
              background: var(--blue); border-radius: 4px; padding: 1px 7px; margin-left: 8px; }
  /* ---- which Jenkins job owns this box ---- */
  .jobpill { display: inline-block; font-size: 9px; font-weight: 700; letter-spacing: .2px;
             font-family: Consolas, "DejaVu Sans Mono", monospace; color: var(--grey);
             background: #F4F4F4; border: 1px solid var(--line);
             border-radius: 4px; padding: 1px 6px; margin-left: 6px; }

  .env-chips { display: flex; gap: 8px; align-items: stretch; flex: 1 1 auto; }
  .echip { flex: 1 1 0; background: #FFFFFF; border: 1px solid var(--line);
           border-radius: 10px; padding: 14px 7px; text-align: center;
           font-size: 11px; font-weight: 600; color: var(--ink);
           box-shadow: 0 1px 2px rgba(0,0,0,.05);
           display: flex; align-items: center; justify-content: center; }
  .earrow { flex: 0 0 13px; display: flex; align-items: center; justify-content: center;
            font-size: 13px; color: var(--ink); }

  /* ---- the dashed tail: each app tier reaches down to the data tier ---- */
  .env::after { content: ""; position: absolute; left: 50%; bottom: -20px; height: 20px;
                border-left: 1.4px dashed #8A8A8A; }

  /* ---- the data tier: one PostgreSQL host, both environments reach it ---- */
  .datarow { margin-top: 20px; }
  .dbcard { position: relative; z-index: 5; background: #FFFFFF; border: 1.5px solid var(--postgres);
            border-radius: 10px; padding: 9px 13px 10px 13px;
            box-shadow: 0 1px 3px rgba(0,0,0,.07); }
  .db-head { display: flex; align-items: center; gap: 10px; }
  .db-head .wordmark { font-size: 12px; font-weight: 800; color: var(--postgres); }
  .db-head .wordmark i { font-style: normal; background: var(--postgres); color: #FFFFFF;
                         border-radius: 4px; font-size: 9px; padding: 2px 6px;
                         letter-spacing: .5px; margin-right: 6px; }
  .db-head .hostpill.db { color: var(--postgres); }
  .db-body { display: flex; align-items: center; gap: 14px; margin-top: 7px; }
  .dbdb b { font-family: Consolas, "DejaVu Sans Mono", monospace; font-size: 11px;
            color: var(--ink); font-weight: 700; }
  .dbdb span { display: block; font-size: 9.5px; color: var(--grey); margin-top: 1px; }
  .dbsep { flex: 0 0 1px; align-self: stretch; background: var(--line); }
  .dbnote { margin-left: auto; font-size: 9.5px; color: var(--grey); text-align: right;
            line-height: 1.45; }
  .dbnote b { color: var(--ink); font-weight: 700; }

  /* ---- the manual approval task ---- */
  .approval { position: relative; flex: 0 0 186px; background: #FFFFFF;
              border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px 12px 12px;
              box-shadow: 0 1px 3px rgba(0,0,0,.07); }
  .approval-h { font-size: 11.5px; font-weight: 700; color: var(--ink); text-align: center;
                border-bottom: 1px solid var(--line); padding-bottom: 6px; }
  /* the job the approval lives in — the gate IS a job boundary */
  .jobtag { font-size: 9px; font-weight: 700; letter-spacing: .4px;
            font-family: Consolas, "DejaVu Sans Mono", monospace; color: #FFFFFF;
            background: var(--grey); border-radius: 4px; padding: 2px 0;
            margin: 8px 0 0 0; text-align: center; }
  .approval p { font-size: 10.5px; color: var(--grey); margin: 9px 0 10px 0;
                line-height: 1.4; text-align: center; }
  .dotted { border-top: 1px dotted #AAAAAA; margin-bottom: 10px; }
  .btn { display: block; text-align: center; font-size: 12.5px; font-weight: 700;
         color: #FFFFFF; border-radius: 6px; padding: 8px 0; margin-bottom: 8px; }
  .btn.reject { background: #D40000; }
  .btn.ok { background: #4CAF50; }

  /* ---- the green arrow from the approval to production ---- */
  .greenarrow { flex: 0 0 34px; align-self: center;
                display: flex; align-items: center; justify-content: center; }
  .greenarrow .line { flex: 1 1 auto; border-top: 2px dashed #3DA35D; position: relative; }
  .greenarrow .line::after { content: ""; position: absolute; right: -1px; top: -5px;
                              border-left: 8px solid #3DA35D; border-top: 5px solid transparent;
                              border-bottom: 5px solid transparent; }

  /* ================= the CI band ================= */
  .ci-chips { display: flex; gap: 10px; align-items: stretch; }
  .cchip { flex: 1 1 0; background: #FFFFFF; border: 1px solid #B9C7DC; border-radius: 12px;
           padding: 11px 6px; text-align: center; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  .cchip .wordmark { display: inline-block; font-size: 10.5px; font-weight: 800;
                     letter-spacing: .5px; color: #FFFFFF; border-radius: 5px;
                     padding: 3px 8px; margin-bottom: 8px; }
  .cchip .t { font-size: 11px; font-weight: 600; color: var(--ink); }
  .cchip.gate { border-color: var(--green); }
  .cchip.gate .t { color: var(--green); }
  .carrow { flex: 0 0 14px; display: flex; align-items: center; justify-content: center;
            font-size: 13px; color: var(--ink); }

  /* ================= the legend, one thin line under the canvas ================= */
  .legend { display: flex; flex-wrap: wrap; gap: 3px 18px; margin-top: 12px;
            font-size: 10px; color: var(--grey); }
  .legend span { display: flex; align-items: center; gap: 5px; }
  .legend i { width: 16px; height: 16px; border-radius: 50%; background: var(--yellow);
              border: 1px solid var(--yellowedge); color: var(--yellowink); font-style: normal;
              font-size: 9px; font-weight: 700; display: inline-flex; align-items: center;
              justify-content: center; flex: 0 0 16px; }

  /* ================= the hosts live on the boxes themselves ================= */
  /* There is no host rail under the canvas: the host of every box is
     written on the box, which is where a reader of the graph looks. */
""")


# --------------------------------------------------------------------------- #
#  The content
# --------------------------------------------------------------------------- #
LEGEND = [
    (1, "GitHub &rarr; Jenkins"),
    (2, "the webhook starts the run"),
    (3, "the data tier &mdash; one PostgreSQL host, .103"),
    (4, "the approval gate &mdash; in the PROD job"),
    (5, "one private repo, pinned"),
    (6, "PROD live"),
]

# (wordmark, class, title, is a gate)
CI_CHIPS = [
    ("TRIVY", "trivy", "Code Scan", True),
    ("PODMAN", "podman", "Build Image", False),
    ("PODMAN", "podman", "Push to Registry", False),
    ("AQUA", "aqua", "Image Scan", True),
]

ENV_CHIPS = {
    "uat": ["Pull Image", "Deploy", "Deploy Database &amp; Application"],
    "prod": ["Pull Image", "Deploy", "Deploy Database &amp; Application"],
}


def env_box(kind: str, title: str, num: int = 0, extra: str = "",
            num_style: str = "left:-16px; top:-16px;", host: str = "",
            job: str = "") -> str:
    chips = "".join(
        (f'<div class="echip">{t}</div>'
         + ('<div class="earrow">&rarr;</div>' if i < len(ENV_CHIPS[kind]) - 1 else ""))
        for i, t in enumerate(ENV_CHIPS[kind]))
    callout = (f'<div class="callout" style="{num_style}">{num}</div>' if num else "")
    hostpill = f'<span class="env-host">{host}</span>' if host else ""
    jobpill = f'<span class="jobpill">job {job}</span>' if job else ""
    return (f'<div class="env {kind}">{callout}{extra}'
            f'<div class="env-t">{title}{hostpill}{jobpill}</div>'
            f'<div class="env-chips">{chips}</div></div>')


# the data tier: one PostgreSQL host (.103) that BOTH application tiers reach
# over the network, with one database and one role per environment
DATATIER = (
    '<div class="dbcard">'
    '<div class="callout" style="left:-15px; top:-15px;">3</div>'
    '<div class="db-head">'
    '<span class="wordmark"><i>PSQL</i>PostgreSQL</span>'
    '<span class="hostpill db">192.168.147.103 &middot; the data tier</span>'
    '</div>'
    '<div class="db-body">'
    '<div class="dbdb"><b>engg_intranet_uat</b>'
    '<span>role engg_uat &middot; used by UAT on .104</span></div>'
    '<div class="dbsep"></div>'
    '<div class="dbdb"><b>engg_intranet</b>'
    '<span>role engg_prod &middot; used by PROD on .105</span></div>'
    '<div class="dbnote">one host &middot; one instance &middot; a role and a grant each,<br>'
    'so UAT cannot open the PROD database<br>'
    'the intranet DR site joins this host later</div>'
    '</div>'
    '</div>'
)

# the dashed elbow that comes in from the far left and points at the box
HOOKIN = '<div class="hookh"></div>'


def build_html() -> str:
    ci_chips = "".join(
        (f'<div class="cchip{" gate" if gate else ""}">'
         f'<div><span class="wordmark brand {cls}">{wm}</span></div>'
         f'<div class="t">{t}</div>'
         + '</div>'
         + ('<div class="carrow">&rarr;</div>' if i < len(CI_CHIPS) - 1 else ""))
        for i, (wm, cls, t, gate) in enumerate(CI_CHIPS))

    legend = "".join(f'<span><i>{n}</i>{t}</span>' for n, t in LEGEND)

    body = f"""
  <div class="canvas">

    <!-- ================= LEFT: the SCM ================= -->
    <div class="leftcol">
      <div class="legend2">
        <div class="callout plain" style="margin-left:-40px;">2</div>
        <div class="txt">
          <b>GitHub and Jenkins</b>
          via Webhooks
        </div>
      </div>

      <div class="gitbox">
        <div class="callout" style="left:-16px; top:-16px;">5</div>
        <div class="wordmark"><i>GH</i> GitHub</div>
        <div class="sub">Private GitHub Repo</div>
        <div class="conn">
          <div class="num">1</div>
          <div class="line"></div>
        </div>
      </div>
    </div>

    <!-- ================= RIGHT: CD over CI ================= -->
    <div class="rightcol">

      <!-- ---------- CD ---------- -->
      <div class="band cd">
        <div class="band-h">
          <span class="brands">
            <span class="brand ansible">ANSIBLE</span>
            <span class="brand podman">PODMAN</span>
          </span>
          <span class="band-title">CD (Continuous Deployment)
            <span class="hostpill">192.168.147.104 &rarr; 192.168.147.105</span>
          </span>
        </div>
        <div class="band-b">
          <div class="env-row">

            {env_box("uat", "UAT Environment", 0, HOOKIN,
                     host="192.168.147.104 &middot; with CI",
                     job="pipeline-uat")}

            <div class="approval">
              <div class="callout" style="left:-16px; top:-16px;">4</div>
              <div class="approval-h">Manual Approval Task</div>
              <div class="jobtag">JOB &middot; pipeline-prod</div>
              <p>Promote the same image to production?</p>
              <div class="dotted"></div>
              <div class="btn reject">Reject</div>
              <div class="btn ok">Approval</div>
            </div>

            <div class="greenarrow"><div class="line"></div></div>

            {env_box("prod", "Production Environment", 6,
                     num_style="right:-15px; top:-15px;",
                     host="192.168.147.105",
                     job="pipeline-prod")}

          </div>

          <!-- ---------- the data tier, under both application tiers ---------- -->
          <div class="datarow">{DATATIER}</div>

          <div class="band-note">UAT and PROD are <b>two separate Jenkins jobs</b>
            &mdash; the promotion is a job boundary, not a step inside one build.
            The UAT job writes a promotion record; the PROD job reads it, and a
            human approves before it deploys. A push to GitHub can never reach
            production.</div>
        </div>
      </div>

      <!-- ---------- CI ---------- -->
      <div class="band ci">
        <div class="band-h">
          <span class="brands"><span class="brand github">GITHUB</span></span>
          <span class="band-title">CI (Continuous Integration)
            <span class="hostpill">192.168.147.104</span>
            <span class="jobpill">job pipeline-uat</span>
          </span>
        </div>
        <div class="band-b">
          <div class="ci-chips">{ci_chips}</div>
          <div class="band-note">Jenkins, the image registry and Aqua &mdash; this host
            carries UAT as well, so untrusted build work never touches PROD</div>
        </div>
      </div>

    </div>
  </div>

  <div class="legend">{legend}</div>
"""

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Pipeline design</title>
<style>{CSS.substitute(**PALETTE)}</style></head>
<body><div class="sheet">
  <div class="rule"></div>
  {body}
</div></body></html>
"""


def main() -> int:
    html_path = HERE / "diagram-design.html"
    png_path = HERE / "Pipeline-Design-UAT-PROD.png"

    html_path.write_text(build_html(), encoding="utf-8")
    print(f"wrote {html_path}")

    if "--html" in sys.argv:
        return 0

    render(html_path, png_path, 1500, 880)
    return 0


if __name__ == "__main__":
    sys.exit(main())
