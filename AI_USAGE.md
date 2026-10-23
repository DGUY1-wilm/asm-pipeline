# AI Usage

I used an AI assistant (Claude) as a pair-programming mentor throughout this project. I'm
documenting that here honestly and in detail, because being transparent about how I used AI
is part of doing the work responsibly — and because I want to be able to speak to it
accurately in interviews.

## How I worked with it

The AI acted as a mentor, not an autopilot. For each step it explained the concept, often
generated code or commands, and reviewed what I wrote. **I ran everything myself**, read the
output, hit the real errors, and worked through them. Many steps only worked after several
rounds of debugging that I drove. The AI did not have access to my machines; it could only
see what I chose to paste or screenshot, so every result in this project is real output from
my own lab, not invented by the AI.

I made the design decisions (scope, scoring rules, SLA policy, what to fix and what to leave
open) and can explain every part of the project, including the code the AI generated.

## What was AI-generated

The AI wrote most of the Python and much of the boilerplate. I reviewed, ran, and in places
corrected it. AI-generated files and content include:

- **Python pipeline:** `src/asm/db.py`, `parse_nmap.py`, `parse_openvas.py`, `enrich.py`,
  `score.py`, `report.py`, `openvas_scan.py`, `tickets.py`
- **Tests:** the `tests/` suite and the fixture XML files
- **Config scaffolding:** `config/owners.yaml`, `config/sla.yaml`, `.gitignore`,
  `pytest.ini`, `requirements*.txt`, the GitHub Actions workflow (`.github/workflows/ci.yml`)
- **Most shell commands** I ran during setup, scanning, and troubleshooting
- **Documentation:** this file, `README.md`, and `GETTING_STARTED.md` were AI-drafted and
  then edited by me
- **Diagrams:** `docs/00-architecture.png` and `docs/01-lab-topology.png` were AI-generated
  from my actual lab setup

## What I did myself

- **Built and configured the entire lab:** installed VirtualBox and the three VMs, set up the
  isolated host-only network, and configured adapters, memory, and snapshots.
- **Ran every scan and command** and verified the output against what I expected (for
  example, checking that database row counts matched the scanner's reported findings, and
  that reruns were idempotent).
- **Debugged the real-world problems**, which was most of the effort:
  - A Windows 11 Hyper-V conflict that forced VirtualBox into a slow mode and stopped
    Metasploitable from booting — diagnosed via the execution-engine indicator and fixed on
    the Windows side.
  - A broken OpenVAS/GVM setup: wrong file ownership for the service account, a missing feed
    import owner, and a web-interface version mismatch (a 404 on the login endpoint) that I
    traced and worked around by driving the scanner through its API instead.
  - Credentialed Windows scanning over SMB, including scoping the firewall to the scanner's
    IP and confirming the login actually succeeded before trusting results.
  - A legacy `sed` option difference on the old Metasploitable OS.
- **Caught mistakes**, including code the AI pasted into the wrong file (recovered with Git)
  and command typos I spotted in the output.
- **Made the judgment calls:** the scope rule, the P1–P4 scoring logic and thresholds, the
  SLA days, grouping tickets by service, which findings to remediate, and recognizing that an
  end-of-life OS can't be fully fixed by patching.
- **Wrote at least one test myself** and can walk through any test in the suite.

## Why I'm documenting this

Using AI well is a real skill, and so is being honest about it. I treated the assistant the
way I'd treat a senior engineer pairing with me: I let it explain and draft, but I owned the
verification, the debugging, and the decisions. The result is a project I understand end to
end and can defend line by line.
