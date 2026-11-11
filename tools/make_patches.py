#!/usr/bin/env python3
"""
Generate the PS17-SEC patch set against a pristine PrestaShop 1.7.8.11 tree.

Each fix is a separate commit so git format-patch emits clean, individually
appliable diffs. Anchors are matched exactly; a miss aborts rather than
silently skipping. The commit date is pinned so rebuilding is byte-identical.
"""
import os, shutil, stat, subprocess, sys, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, ".work")
SRC = os.path.join(WORK, "src")
OUT = os.path.join(REPO, "patches")
TARBALL = os.path.join(WORK, "ps17.tar.gz")
TARBALL_URL = "https://github.com/PrestaShop/PrestaShop/archive/refs/tags/1.7.8.11.tar.gz"
FIXED_DATE = "2026-11-10T12:00:00+00:00"


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def sh(*args, **kw):
    kw.setdefault("cwd", SRC)
    kw.setdefault("check", True)
    env = dict(os.environ)
    env["GIT_AUTHOR_DATE"] = FIXED_DATE
    env["GIT_COMMITTER_DATE"] = FIXED_DATE
    kw.setdefault("env", env)
    return subprocess.run(args, **kw)


def edit(relpath, old, new, count=1):
    path = os.path.join(SRC, relpath)
    with open(path, "r", encoding="utf-8", newline="") as fh:
        body = fh.read()
    found = body.count(old)
    if found != count:
        sys.exit("ANCHOR FAIL in %s: expected %d, found %d\n--- anchor ---\n%s"
                 % (relpath, count, found, old[:300]))
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(body.replace(old, new, count))
    print("  patched %s" % relpath)


def commit(msg):
    sh("git", "add", "-A")
    sh("git", "commit", "-q", "-m", msg)
    print("  committed: %s" % msg.splitlines()[0])


print("== preparing pristine tree ==")
if not os.path.isdir(WORK):
    os.makedirs(WORK)
if not os.path.isfile(TARBALL):
    print("  downloading PrestaShop 1.7.8.11 ...")
    urllib.request.urlretrieve(TARBALL_URL, TARBALL)
if os.path.isdir(SRC):
    shutil.rmtree(SRC, onerror=_force_remove)
os.makedirs(SRC)
subprocess.run(["tar", "xzf", TARBALL, "-C", SRC, "--strip-components=1"],
               cwd=WORK, check=True)
print("  extracted pristine 1.7.8.11")

sh("git", "init", "-q")
sh("git", "config", "core.autocrlf", "false")
sh("git", "config", "core.eol", "lf")
sh("git", "config", "user.email", "patches@example.invalid")
sh("git", "config", "user.name", "PS17-SEC")
sh("git", "add", "-A")
sh("git", "commit", "-q", "-m", "pristine PrestaShop 1.7.8.11")
base = subprocess.run(["git", "rev-list", "--max-parents=0", "HEAD"],
                      cwd=SRC, check=True, capture_output=True,
                      text=True).stdout.strip()

# --------------------------------------------------------------------------
# PSEC-0001 / CVE-2026-44212
# --------------------------------------------------------------------------
print("\n== PSEC-0001 CVE-2026-44212 stored XSS in customer service view ==")
TPL = "admin-dev/themes/default/template/controllers/customer_threads/helpers/view/view.tpl"

edit(TPL,
     "{else} {$thread->email}{/if}</h3>",
     "{else} {$thread->email|escape:'html':'UTF-8'}{/if}</h3>")

edit(TPL,
     '<input type="hidden" name="msg_email" value="{$thread->email}" />',
     '<input type="hidden" name="msg_email" value="{$thread->email|escape:\'html\':\'UTF-8\'}" />')

commit("""PSEC-0001: escape thread email in customer service view (CVE-2026-44212)

An unauthenticated visitor submits the public Contact Us form with a payload
in the email field. It is stored, then rendered unescaped when a back-office
employee opens the thread, giving session hijacking and back-office takeover.

Two sites in the same template render $thread->email without escaping: the
reply form heading and the hidden msg_email input. The <h2> thirty lines
earlier in the same file already escapes it, which is what makes this an
oversight rather than a convention.

Backported from the upstream fix shipped in PrestaShop 8.2.6 and 9.1.1. The
template change is identical; the escape filter and syntax are unchanged
between 1.7 and 8.x.

NOT backported: upstream also switched Validate::isEmail() from Symfony's
'loose' to 'strict' email validation mode as defence in depth. PrestaShop 1.7
does not use Symfony's validator there. It uses egulias/EmailValidator with
RFCValidation and SwiftMailerValidation, which has no equivalent mode switch.
Tightening it would mean choosing a different validation strategy, which is a
behaviour change affecting every email field on the site, not a backport. See
advisories/PSEC-0001.md.

Advisory: https://github.com/advisories/GHSA-w9f3-qc75-qgx9""")

# --------------------------------------------------------------------------
print("\n== writing patches ==")
if not os.path.isdir(OUT):
    os.makedirs(OUT)
for stale in os.listdir(OUT):
    if stale.endswith(".patch"):
        os.remove(os.path.join(OUT, stale))

sh("git", "format-patch", "-q", "--no-signature", "--zero-commit",
   "--no-numbered", "-o", OUT, base)

count = len([f for f in os.listdir(OUT) if f.endswith(".patch")])
for name in sorted(os.listdir(OUT)):
    if name.endswith(".patch"):
        print("  %s (%d bytes)" % (name, os.path.getsize(os.path.join(OUT, name))))
print("\nDone. %d patch(es) generated." % count)
