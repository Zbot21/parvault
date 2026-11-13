#!/usr/bin/env python3
"""L-34 docs-commands gate (plan-7 section 3): every command block in README.md and QUICKSTART.md
runs verbatim against the release binaries, or carries a reasoned skip.

  extract          write docs/doc-commands.txt (one command per line, checked in for review)
  check [--base R] fail if docs/doc-commands.txt is stale, a block or fence is malformed, the
                   skip count differs from docs/doc-commands.ratchet, or (with --base) the
                   ratchet grew since git ref R (CI passes the merge base: skips never increase)
  run BIN          run every non-skipped block in Docker (ubuntu:24.04, BIN on PATH, no toolchain)
  selftest         the runner's positive controls on fixture docs, locally (no Docker)

Annotations: HTML comments on the lines right before a ```bash or ```sh fence.
  <!-- doc-cmd: skip reason="..." -->        not run; listed in the summary; counted by the ratchet
  <!-- doc-cmd: env K=V [K=V ...] -->        exported for this block
  <!-- doc-cmd: expect-exit N -->            the block must exit N (default 0)
  <!-- doc-cmd: capture NAME="regex" -->     group 1 of regex in the output fills <NAME> later
  <!-- doc-cmd: node NAME -->                container to run in (default "main"; one per doc)
  <!-- doc-cmd: background ready="text" -->  a long-running command: started detached; the block
                                             passes when "text" appears in its output
"""
import os
import re
import shlex
import subprocess
import sys
import time

DOCS = ["README.md", "QUICKSTART.md"]
OUT = "docs/doc-commands.txt"
RATCHET = "docs/doc-commands.ratchet"
ANN_RE = re.compile(r"^\s*<!--\s*doc-cmd:\s*(.*?)\s*-->\s*$")
# GitHub renders ``` and ~~~ fences of any length >= 3; the closing run is the same character,
# at least as long.
FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)\s*$")
SHELL_LANGS = {"bash", "sh"}
# Fences that hold no commands to run. Any other fence (bare, console, shell, zsh, ...) fails the
# check unless it carries a doc-cmd annotation, so a runnable block cannot hide from the gate.
NON_COMMAND_LANGS = {"mermaid", "text", "json", "toml", "yaml", "html", "javascript", "js", "rust",
                     "diff", "ini", "csv", "xml"}
PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9_]*)>")
IMAGE = "parvault-doc-commands:ubuntu-24.04"
BLOCK_TIMEOUT = 180
READY_TIMEOUT = 60


class Block:
    def __init__(self, doc, line, lines, ann):
        self.doc, self.line, self.raw, self.ann = doc, line, lines, ann

    def commands(self):
        out, cur = [], ""
        for l in self.raw:
            s = l.rstrip()
            if cur:
                cur += " " + s.strip()
            else:
                if not s.strip() or s.strip().startswith("#"):
                    continue
                cur = s.strip()
            if cur.endswith("\\"):
                cur = cur[:-1].rstrip()
                continue
            out.append(cur)
            cur = ""
        if cur:
            out.append(cur)
        return out

    def where(self):
        return f"{self.doc}:{self.line}"


def parse_ann(text, where):
    ann = {"env": [], "capture": []}
    kind, _, rest = text.partition(" ")
    if kind == "skip":
        m = re.fullmatch(r'reason="([^"]+)"', rest.strip())
        if not m:
            sys.exit(f"{where}: skip needs reason=\"...\"")
        ann["skip"] = m.group(1)
    elif kind == "env":
        ann["env"] = shlex.split(rest)
        if not all("=" in kv for kv in ann["env"]):
            sys.exit(f"{where}: env takes K=V pairs")
    elif kind == "expect-exit":
        ann["expect"] = int(rest)
    elif kind == "capture":
        m = re.fullmatch(r'([A-Z][A-Z0-9_]*)="(.+)"', rest.strip())
        if not m:
            sys.exit(f'{where}: capture takes NAME="regex"')
        ann["capture"] = [(m.group(1), m.group(2))]
    elif kind == "node":
        ann["node"] = rest.strip()
    elif kind == "background":
        m = re.fullmatch(r'ready="([^"]+)"', rest.strip())
        if not m:
            sys.exit(f"{where}: background needs ready=\"...\"")
        ann["ready"] = m.group(1)
    else:
        sys.exit(f"{where}: unknown doc-cmd annotation '{kind}'")
    return ann


def merge(a, b):
    for k, v in b.items():
        if k in ("env", "capture"):
            a.setdefault(k, []).extend(v)
        else:
            a[k] = v
    return a


def blocks(root, docs=DOCS):
    """The shell blocks of `docs`, and the problems found in their fences and annotations."""
    found, problems = [], []
    empty = {"env": [], "capture": []}
    for doc in docs:
        lines = open(os.path.join(root, doc), encoding="utf-8").read().split("\n")
        pending, i = dict(empty, env=[], capture=[]), 0
        while i < len(lines):
            m = ANN_RE.match(lines[i])
            if m:
                pending = merge(pending, parse_ann(m.group(1), f"{doc}:{i + 1}"))
                i += 1
                continue
            f = FENCE_RE.match(lines[i])
            if f:
                indent, run, lang = f.group(1), f.group(2), f.group(3).lower()
                annotated = pending != empty
                close = re.compile("^" + re.escape(run[0]) + "{" + str(len(run)) + ",}$")
                start, body = i + 1, []
                i += 1
                while i < len(lines) and not close.match(lines[i].strip()):
                    body.append(lines[i])
                    i += 1
                if lang in SHELL_LANGS and not indent:
                    found.append(Block(doc, start, body, pending))
                elif lang in SHELL_LANGS:
                    problems.append(f"{doc}:{start}: indented ```{lang} fence: the gate runs only column-0 shell fences; unindent it")
                elif annotated:
                    # A non-shell fence can only be skipped (counted by the ratchet); any other
                    # annotation would make the check accept a block the runner never runs.
                    if set(k for k, v in pending.items() if v) == {"skip"}:
                        found.append(Block(doc, start, body, pending))
                    else:
                        problems.append(f"{doc}:{start}: ```{lang or '(bare)'} fence carries a doc-cmd annotation other than skip: only skip is allowed on a non-shell fence")
                elif lang not in NON_COMMAND_LANGS:
                    problems.append(f"{doc}:{start}: ```{lang or '(bare)'} fence is neither a shell block nor an allowlisted language ({', '.join(sorted(NON_COMMAND_LANGS))}): use ```bash or annotate it")
                pending = dict(empty, env=[], capture=[])
            elif lines[i].strip():
                if pending != empty:
                    problems.append(f"{doc}:{i + 1}: doc-cmd annotation not directly before a bash/sh block")
                    pending = dict(empty, env=[], capture=[])
            i += 1
    return found, problems


def render(bl):
    out = ["# Generated by scripts/doc_commands.sh extract (plan-7 L-34 gate); do not edit.",
           "# Every bash/sh block in README.md and QUICKSTART.md, one command per line."]
    for b in bl:
        tags = [f"node={b.ann.get('node', 'main')}"]
        if "skip" in b.ann:
            tags.append(f'skip="{b.ann["skip"]}"')
        if "ready" in b.ann:
            tags.append(f'background ready="{b.ann["ready"]}"')
        if "expect" in b.ann:
            tags.append(f"expect-exit={b.ann['expect']}")
        tags += [f"env {kv}" for kv in b.ann["env"]]
        tags += [f'capture {n}="{r}"' for n, r in b.ann["capture"]]
        out.append("")
        out.append(f"## {b.where()} " + " ".join(tags))
        out += b.commands()
    return "\n".join(out) + "\n"


def base_ratchet(root, ref):
    """The ratchet value at git ref `ref`, or None if the file did not exist there."""
    r = subprocess.run(["git", "-C", root, "show", f"{ref}:{RATCHET}"], capture_output=True, text=True)
    return int(r.stdout.split()[1]) if r.returncode == 0 else None


def check(root, bl, fence_problems, base=None):
    problems = list(fence_problems)
    want = render(bl)
    have = open(os.path.join(root, OUT), encoding="utf-8").read() if os.path.exists(os.path.join(root, OUT)) else ""
    if want != have:
        problems.append(f"{OUT} is stale: run scripts/doc_commands.sh extract")
    skips = sum(1 for b in bl if "skip" in b.ann)
    ratchet = int(open(os.path.join(root, RATCHET)).read().split()[1])
    if skips != ratchet:
        problems.append(f"{skips} skipped block(s) but {RATCHET} says {ratchet}; update it in the same commit")
    if base:
        if subprocess.run(["git", "-C", root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
                          capture_output=True).returncode != 0:
            problems.append(f"--base {base} is not a commit here (shallow clone? CI needs fetch-depth: 0)")
        before = base_ratchet(root, base)
        if before is not None and ratchet > before:
            problems.append(f"the skip ratchet grew from {before} (at {base}) to {ratchet}: skips may only decrease")
    captured = set()
    for b in bl:
        if "skip" in b.ann:
            continue
        for name in PLACEHOLDER_RE.findall("\n".join(b.commands())):
            if name not in captured:
                problems.append(f"{b.where()}: placeholder <{name}> has no earlier capture (capture it or skip the block)")
        captured |= {n for n, _ in b.ann["capture"]}
    problems += claim_problems(root)
    for p in problems:
        print("[FAIL]", p)
    print(f"doc-commands: {len(bl)} block(s), {len(bl) - skips} run, {skips} skipped (ratchet {ratchet})")
    return not problems


CLAIMS = "docs/claims-pending.txt"
CLAIM_TAG = {"planned": "<!-- claim: planned -->(planned)", "stubbed": "<!-- claim: stubbed -->(stub)"}
CLAIM_RE = re.compile(r"<!--\s*claim:\s*(\w+)\s*-->(\(\w+\))?")


def claim_problems(root):
    """Every pending audit claim (docs/claims-pending.txt) carries its label on its line, and
    every label in the docs is a known marker followed by its visible tag."""
    problems, rows = [], []
    for n, line in enumerate(open(os.path.join(root, CLAIMS), encoding="utf-8"), 1):
        if line.strip() and not line.startswith("#"):
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 4 or parts[2] not in CLAIM_TAG:
                problems.append(f"{CLAIMS}:{n}: want 'file | anchor | planned|stubbed | audit row'")
                continue
            rows.append(parts)
    for doc, anchor, label, ref in rows:
        hits = [l for l in open(os.path.join(root, doc), encoding="utf-8") if anchor in l]
        if not hits:
            problems.append(f"{doc}: claim anchor '{anchor}' not found: fixed? remove its {CLAIMS} row")
        elif not any(CLAIM_TAG[label] in l for l in hits):
            problems.append(f"{doc}: '{anchor}' ({ref}) lacks '{CLAIM_TAG[label]}'")
    for doc in DOCS:
        for n, l in enumerate(open(os.path.join(root, doc), encoding="utf-8"), 1):
            for m in CLAIM_RE.finditer(l):
                if m.group(1) not in CLAIM_TAG or not l[m.start():].startswith(CLAIM_TAG[m.group(1)]):
                    problems.append(f"{doc}:{n}: claim marker must be one of {list(CLAIM_TAG.values())}")
    return problems


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


class DockerNode:
    """One container per document and node; blocks run there as files, stdin closed."""
    tmp = "/tmp"

    def __init__(self, name, net, bindir):
        self.name = name
        sh(["docker", "rm", "-f", name])
        r = sh(["docker", "run", "-d", "--name", name, "--network", net, "--hostname", name.rsplit("-", 1)[-1],
                "-v", f"{bindir}:/opt/parvault/bin:ro",
                "-e", "PATH=/opt/parvault/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "-w", "/root", IMAGE, "sleep", "infinity"])
        if r.returncode:
            sys.exit(f"cannot start {name}: {r.stderr}")

    def put(self, path, content):
        r = subprocess.run(["docker", "exec", "-i", self.name, "sh", "-c", f"cat > {path}"],
                           input=content, capture_output=True, text=True)
        if r.returncode:
            sys.exit(f"cannot write {path} in {self.name}: {r.stderr}")

    def exec(self, cmd, timeout=None, detach=False):
        args = ["docker", "exec"] + (["-d"] if detach else []) + [self.name, "bash", "-c", cmd]
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)

    def close(self):
        sh(["docker", "rm", "-f", self.name])


class LocalNode:
    """The same interface on this machine, in a temp HOME (selftest only)."""

    def __init__(self, name, net, bindir):
        import tempfile
        self.home = tempfile.mkdtemp(prefix="pvdoc-selftest-")
        self.tmp = self.home

    def put(self, path, content):
        open(path, "w").write(content)

    def exec(self, cmd, timeout=None, detach=False):
        env = dict(os.environ, HOME=self.home)
        if detach:
            subprocess.Popen(["bash", "-c", cmd], cwd=self.home, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            return subprocess.CompletedProcess([], 0, "", "")
        return subprocess.run(["bash", "-c", cmd], cwd=self.home, env=env, capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)

    def close(self):
        import shutil
        r = self.exec("for f in *.pid; do [ -f \"$f\" ] && kill \"$(cat \"$f\")\" 2>/dev/null; done; true")
        shutil.rmtree(self.home, ignore_errors=True)


def run_blocks(bl, node_for, ready_timeout=READY_TIMEOUT):
    """Runs `bl` in order; returns [(block, PASS|FAIL|SKIP, detail)]."""
    results, captures = [], {}
    for n, b in enumerate(bl):
        if "skip" in b.ann:
            results.append((b, "SKIP", b.ann["skip"]))
            continue
        node = node_for(b)
        cmds = "\n".join(b.commands())
        for name, val in captures.items():
            cmds = cmds.replace(f"<{name}>", val)
        env = "".join(f"export {shlex.quote(kv.split('=', 1)[0])}={shlex.quote(kv.split('=', 1)[1])}\n"
                      for kv in b.ann["env"])
        # set -a: plain assignments (SOCK=..., TOKEN=...) carry to later blocks, as in one shell.
        pre = "set -a -o pipefail\n[ -f ~/.doc-env ] && . ~/.doc-env\n" + env
        script = f"{node.tmp}/doc-block-{n}.sh"
        if "ready" in b.ann:
            log, pid = f"{node.tmp}/doc-bg-{n}.log", f"{node.tmp}/doc-bg-{n}.pid"
            node.put(script, pre + cmds + "\n")
            node.exec(f"echo $$ > {pid}; exec bash -e {script} < /dev/null > {log} 2>&1", detach=True)
            out, status, detail, deadline = "", "FAIL", "", time.time() + ready_timeout
            while time.time() < deadline:
                out = node.exec(f"cat {log} 2>/dev/null").stdout
                alive = node.exec(f"[ -s {pid} ] && kill -0 \"$(cat {pid})\" 2>/dev/null").returncode == 0
                if b.ann["ready"] in out and alive:
                    status, detail = "PASS", "ready"
                    break
                if not alive and node.exec(f"[ -s {pid} ]").returncode == 0:
                    detail = f"exited before it was ready:\n{out[-2000:]}"
                    break
                time.sleep(0.5)
            else:
                detail = f"'{b.ann['ready']}' not seen in {ready_timeout}s:\n{out[-2000:]}"
        else:
            node.put(script, pre + "trap 'export -p > ~/.doc-env' EXIT\n" + cmds + "\n")
            try:
                r = node.exec(f"bash -e {script} < /dev/null", timeout=BLOCK_TIMEOUT)
                out, rc = r.stdout + r.stderr, r.returncode
            except subprocess.TimeoutExpired:
                out, rc = f"timed out after {BLOCK_TIMEOUT}s", None
            want = b.ann.get("expect", 0)
            status = "PASS" if rc == want else "FAIL"
            detail = f"exit {rc}" + ("" if rc == want else f" (want {want}):\n{out[-3000:]}")
        for name, rx in b.ann["capture"]:
            m = re.search(rx, out, re.M)
            if m:
                captures[name] = m.group(1)
            elif status == "PASS":
                status, detail = "FAIL", f"capture {name}: /{rx}/ matched nothing:\n{out[-2000:]}"
        results.append((b, status, detail))
        print(f"[{status}] {b.where()} ({b.ann.get('node', 'main')}): {detail.splitlines()[0] if detail else ''}", flush=True)
        if status == "FAIL":
            print(detail, flush=True)
    return results


def summarize(results):
    print("\nSkipped blocks:")
    for b, s, d in results:
        if s == "SKIP":
            print(f"  {b.where()}: {d}")
    fails = [r for r in results if r[1] == "FAIL"]
    ran = sum(1 for r in results if r[1] != "SKIP")
    print(f"\ndoc-commands run: {ran - len(fails)}/{ran} block(s) passed, {len(results) - ran} skipped")
    return not fails


def run(root, bindir, bl):
    bindir = os.path.realpath(bindir)
    if sh(["docker", "image", "inspect", IMAGE]).returncode != 0:
        df = ("FROM ubuntu:24.04\nRUN apt-get update -o Acquire::Retries=3 && apt-get install -y "
              "--no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*\n")
        if subprocess.run(["docker", "build", "-t", IMAGE, "-"], input=df, text=True).returncode:
            sys.exit("cannot build the doc-commands image")
    net = "pvdoc-net"
    sh(["docker", "network", "create", net])
    nodes = {}

    def node_for(b):
        name = f"pvdoc-{re.sub(r'[^a-z0-9]', '', b.doc.lower())}-{b.ann.get('node', 'main')}"
        if name not in nodes:
            nodes[name] = DockerNode(name, net, bindir)
        return nodes[name]

    try:
        return summarize(run_blocks(bl, node_for))
    finally:
        for nd in nodes.values():
            nd.close()
        sh(["docker", "network", "rm", net])


SELFTEST_DOC = """# fixture
<!-- doc-cmd: capture AFTER="(after-stdin)" -->
```bash
cat >/dev/null
echo after-stdin
```
```bash
cat >/dev/null; false
```
<!-- doc-cmd: background ready="never-printed" -->
```bash
echo starting; exit 1
```
<!-- doc-cmd: background ready="READY-LINE" -->
```bash
echo READY-LINE; sleep 30
```
```mermaid
graph LR
```
```console
$ parvault init
```
  ```bash
  echo indented
  ```
~~~bash
echo tilde-fence
~~~
````bash
echo four-backtick-fence
```
echo still-inside
````
<!-- doc-cmd: env X=1 -->
```console
$ annotated-but-not-shell
```
<!-- doc-cmd: skip reason="example output" -->
```console
$ skipped-console
```
"""


def selftest():
    import tempfile
    root = tempfile.mkdtemp(prefix="pvdoc-fixture-")
    open(os.path.join(root, "FIXTURE.md"), "w").write(SELFTEST_DOC)
    bl, problems = blocks(root, ["FIXTURE.md"])
    ok = True

    def expect(cond, what):
        nonlocal ok
        print(("[PASS] " if cond else "[FAIL] ") + what)
        ok = ok and cond

    runnable = [b for b in bl if "skip" not in b.ann]
    expect(len(runnable) == 6, f"6 runnable shell blocks, including ~~~bash and ````bash (got {len(runnable)})")
    expect(any("still-inside" in "\n".join(b.commands()) for b in bl), "a ``` line inside a ````bash fence stays in the block")
    expect(any("```console fence" in p and "only skip" in p for p in problems), "a non-shell fence annotated with env fails the check")
    expect(sum(1 for b in bl if "skip" in b.ann) == 1, "a skipped ```console fence counts toward the ratchet")
    expect(any("```console" in p for p in problems), "an unannotated ```console fence fails the check")
    expect(any("indented ```bash" in p for p in problems), "an indented ```bash fence fails the check")
    expect(not any("```mermaid fence" in p for p in problems), "an allowlisted ```mermaid fence passes")
    node = LocalNode("selftest", None, None)
    try:
        res = run_blocks(bl[:4], lambda b: node, ready_timeout=10)
    finally:
        node.close()
    st = [s for _, s, _ in res]
    expect(st[0] == "PASS", "a command reading stdin does not swallow the rest of its block")
    expect(st[1] == "FAIL", "'cat >/dev/null; false' fails its block")
    expect(st[2] == "FAIL" and "exited before it was ready" in res[2][2], "a background block that dies is not ready")
    expect(st[3] == "PASS", "a live background block that prints its ready line is ready")
    print("doc-commands selftest: " + ("PASS" if ok else "FAIL"))
    return ok


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("extract", "check", "run", "selftest"):
        sys.exit(__doc__)
    if sys.argv[1] == "selftest":
        sys.exit(0 if selftest() else 1)
    root = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    bl, problems = blocks(root)
    if sys.argv[1] == "extract":
        open(os.path.join(root, OUT), "w", encoding="utf-8").write(render(bl))
        print(f"wrote {OUT}: {len(bl)} block(s)")
    elif sys.argv[1] == "check":
        base = sys.argv[3] if len(sys.argv) == 4 and sys.argv[2] == "--base" else None
        sys.exit(0 if check(root, bl, problems, base) else 1)
    else:
        if len(sys.argv) != 3:
            sys.exit("run needs the directory holding the release binaries")
        if not check(root, bl, problems):
            sys.exit(1)
        sys.exit(0 if run(root, sys.argv[2], bl) else 1)


if __name__ == "__main__":
    main()
