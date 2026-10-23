# Getting Started: Build This Lab Yourself

This guide is written for someone with **little or no technical background**. It explains,
in plain language, how to recreate this project from nothing. You do not need to be a
programmer. You need patience, a reasonably powerful computer, and a willingness to follow
steps carefully and read what the screen tells you.

Think of this project as building a tiny, safe, pretend company network inside your own
computer, then playing both the security engineer who finds the weak spots *and* the person
who fixes them.

> **The one rule that matters most:** everything here happens inside "virtual machines" —
> pretend computers that live inside your real computer, walled off on their own private
> network. You are only ever scanning machines you built yourself. Never point these tools
> at a website, a company, a school network, or anyone else's device. That isn't just rude;
> it's illegal.

---

## What you'll end up with

A small pretend network of three computers-inside-your-computer:

- a **scanner** (the security tool, called Kali),
- a **weak Linux machine** (deliberately full of holes, called Metasploitable), and
- a **Windows machine**.

Plus a set of small programs (written in Python) that automatically find the weaknesses,
rank them by how dangerous they are, and track getting them fixed — like a to-do list for
security problems.

---

## Before you start: what you need

- **A computer with at least 16 GB of memory (RAM).** More is better. This runs several
  pretend computers at once, which is demanding.
- **About 100 GB of free disk space.**
- **Windows 11** (this guide assumes it; the tools also exist for Mac and Linux).
- **A few hours, spread over several sittings.** Some steps involve long waits while things
  download or install. That's normal. Don't rush them.

A gentle warning: you *will* hit confusing errors. Everyone does — this project is a record
of me hitting many of them and working through each one. Getting stuck and un-stuck **is**
the learning. When something breaks, read the error message slowly; it is usually trying to
tell you what's wrong.

---

## The big picture (in order)

1. Install the software that runs pretend computers.
2. Build the three pretend computers.
3. Connect them to a private, isolated network.
4. Run the "scanner" to find weaknesses.
5. Let the automatic programs rank the weaknesses and make a report.
6. Fix a few weaknesses, re-scan, and watch them disappear from the list.

Each part below tells you roughly how long it takes and what "done" looks like.

---

## Step 1 — Install VirtualBox (the pretend-computer software)

**What it is:** VirtualBox is a free program that lets your real computer run other,
smaller computers inside windows on your screen. Each one is called a *virtual machine*,
or VM.

**Do this:**
1. Search the web for **"VirtualBox download"** and get it from the official site
   (virtualbox.org).
2. Install it like any normal program (keep clicking Next / Install).

**One common snag:** on Windows 11, a built-in feature called *Hyper-V* can fight with
VirtualBox and make your pretend computers painfully slow or stop them from starting at all.
If that happens later, the fix is to turn off a few Windows security features and restart
your real computer. You'll know you've hit this if a VM hangs forever on a startup screen,
or if a little **green turtle icon** appears at the bottom of the VM window (the turtle means
"running in slow mode"). This is the single most common early roadblock, so don't panic if
you meet it — it's fixable.

**Done when:** VirtualBox opens and shows an empty list of machines.

---

## Step 2 — Build the three pretend computers

Each VM is created inside VirtualBox. You download a "disk image" (a file containing a
ready-made computer) or an installer, then tell VirtualBox to use it.

**The scanner (Kali Linux):**
- On the Kali website, look for the ready-made **VirtualBox** version (not the "installer"
  version — the ready-made one saves a lot of trouble).
- Download it, unzip it, and double-click the file to add it to VirtualBox.

**The weak Linux machine (Metasploitable 2):**
- Download Metasploitable 2. It comes as a ready-made disk, so you don't "install" it — you
  just create a new VM in VirtualBox and point it at that disk.

**The Windows machine:**
- Use a free evaluation copy of Windows from Microsoft, or any Windows VM you have.

Give each machine a sensible amount of memory (for example, 4 GB for Kali and Windows, less
for the weak Linux one). VirtualBox will suggest numbers; the defaults are usually fine.

**Done when:** all three appear in your VirtualBox list and can start up to a login screen.
(Expect the first start of each to be slow.)

---

## Step 3 — Put them on a private, isolated network

This is the safety step. You create a **"host-only" network** in VirtualBox — a private
bubble where your three pretend computers can talk to each other and to your real computer,
but **cannot reach the internet or anything else.**

- In VirtualBox's network settings, create a host-only network (it will have an address
  like `192.168.56.something`).
- Set each VM to use it.
- The scanner (Kali) gets a *second* connection for downloading updates. The two targets
  get **only** the private one, so they can never "escape."

**Done when:** from the Kali machine, you can "ping" (reach) the other two machines by their
addresses, proving they can see each other on the private network.

---

## Step 4 — Find the weaknesses (scanning)

Now you play security engineer. Two kinds of scan:

1. **A map of what's there (Nmap).** This asks each machine "what doors (ports) are open,
   and what's running behind them?" It's like walking around a building and noting every
   door and window.
2. **A check for known problems (OpenVAS).** This takes the map and asks "which of these
   doors have known broken locks?" It compares what's running against a giant database of
   known vulnerabilities.

The first scan is quick. The second takes a while to set up the first time (it downloads a
large database of known vulnerabilities — this can take an hour, mostly unattended) and
20–45 minutes to run. Both are normal.

A nice thing to notice: the Windows machine looks almost empty from the outside because it
blocks probing — but when you let the scanner *log in* with a username and password (a
"credentialed scan"), it finds lots of missing updates on the inside. That difference —
outside view versus inside view — is a real and important lesson.

**Done when:** you have scan results saved as files.

---

## Step 5 — Let the programs rank the problems and make a report

This is where the Python programs earn their keep. You run them one at a time, and each does
one job:

- Read the scan files and store everything neatly.
- Look up, for each problem, **whether it's actually being attacked in the real world**
  (using two free public services: a US-government "known exploited" list and a
  "probability of attack" score).
- **Rank** every problem from most to least urgent, and assign each a pretend owner and a
  deadline.
- Produce a **report** — a single web page you can open in your browser showing everything,
  color-coded by urgency.

You don't need to understand the code to run it. You type a short command, press Enter, and
read what it prints. If something goes wrong, it usually prints a message explaining what.

**Done when:** you open the report in your browser and see your findings, ranked, with
owners and due dates.

---

## Step 6 — Fix things, re-scan, and watch them close

The final, most satisfying part: close the loop.

1. The pipeline opens **tickets** (to-do items) in Jira — a free, widely used task-tracking
   tool — one per problem area, with the urgent ones marked clearly.
2. You **actually fix** a few problems. For the weak Linux machine, that means switching off
   some dangerous old services. For Windows, it means installing updates.
3. You **re-scan**.
4. The pipeline notices the problems are gone and **closes the tickets by itself**, leaving
   a note that says "a re-scan confirmed this is fixed."

Watching a ticket close automatically because you genuinely fixed the underlying problem —
and *proved* it with a fresh scan — is the whole point. That's what real security remediation
looks like.

**Done when:** your fixed problems show as "Done" in Jira, with notes explaining why.

---

## When you get stuck (you will)

- **Read the error slowly.** It is almost always a clue, not gibberish.
- **Note which step you're on and what you just did.** Most problems come from the step
  immediately before.
- **A hang isn't always a crash.** Many steps (first boots, database downloads, scans) just
  take a long time. Give them 20–30 minutes before assuming something's wrong.
- **Search the exact error message.** Someone has almost always hit it before.
- **Take snapshots.** VirtualBox can save a "snapshot" of a working machine — a restore
  point you can roll back to if you break something later. Take one whenever a machine is in
  a good state.

---

## Why this is worth doing

By the end, you won't just have followed a recipe. You'll have built a working network,
found real weaknesses in it, learned to tell the dangerous ones from the noise, fixed some,
and proved the fixes worked — the same cycle real security teams run every day. And you'll
have hit, and solved, a pile of genuine technical problems along the way, which is the part
that actually teaches you.

Take it slowly, be patient with the waits and the errors, and treat every broken step as the
lesson rather than an interruption. That mindset is most of the job.