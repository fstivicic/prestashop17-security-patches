# PS17-SEC — unofficial security patches for PrestaShop 1.7

Free, source-available security backports for **PrestaShop 1.7.8.11**, the last
release of the 1.7 line.

PrestaShop stopped shipping security fixes for 1.7 when PrestaShop 9 was
released in **June 2025**. The last 1.7 release, `1.7.8.11`, was January 2024.
There is **no extended support programme** for 1.7, paid or free.

> **Not affiliated with PrestaShop SA.** Independent and unofficial, no
> endorsement. If you can upgrade to a supported release, do that instead.
> These patches are for shops that cannot, yet.

---

## What is patched

| ID | CVE | Issue | Severity |
|----|-----|-------|----------|
| [PSEC-0001](advisories/PSEC-0001.md) | CVE-2026-44212 | Stored XSS in the back-office customer service view | Critical |

**An unauthenticated visitor can take over the back office.** Submit the public
Contact Us form with a payload in the email field; it fires when staff open the
thread.

The published range is `< 8.2.6`, which numerically includes every 1.7 release.
Unlike the usual end-of-life argument, nobody has to be convinced 1.7 is in
scope — the vendor's own range says so. There is simply no fix shipped for it.

## Verify before trusting it

```sh
php tests/probe.php /path/to/your/prestashop        # is it vulnerable?
php tests/regression.php /path/to/your/prestashop   # does the template still work?
```

On a stock `1.7.8.11` tree the probe reports **1 vector vulnerable** and the
regression harness reports **4 payloads not neutralised**. After the patch:
**0 vulnerable, 18 ok, 0 regressions**, with ordinary addresses — apostrophes,
non-ASCII — still round-tripping exactly.

Both exit non-zero when something is wrong, so they work in CI.

## Applying it

Back up first.

```sh
cd /path/to/your/prestashop
patch -p1 -F0 -i /path/to/ps17-sec/patches/0001-*.patch
```

`-F0` matters. GNU patch defaults to a fuzz factor of 2, which lets context
match at a shifted offset, so the same patch can apply twice. Zero fuzz means
exact context or refusal.

**Do not use `git apply`.** Inside a git repository it resolves paths from the
repository root and silently ignores paths outside it, exiting 0 having changed
nothing.

### File touched

```
admin-dev/themes/default/template/controllers/customer_threads/helpers/view/view.tpl
```

If your shop uses a custom admin theme, check whether it overrides this
template. If it does, the same two lines need the same filter there.

## Rebuilding the patches

```sh
python tools/make_patches.py
```

Downloads 1.7.8.11 if not cached, applies each fix as its own commit, and emits
the patches. The commit date is pinned so rebuilds are byte-identical.

## Honest limits

- **The proof is template analysis, not exploitation.** The probe verifies every
  render site escapes. It does not stand up PrestaShop and run the attack.
- **One template examined.** Other unescaped renderings elsewhere in the 1.7
  back office are likely and were not searched for.
- **1.7.8.11 only.** Earlier 1.7.x releases probably share the defect but were
  not tested.
- **Part of the upstream fix is deliberately omitted.** Upstream also tightened
  email validation, which 1.7 cannot do the same way. Approximating it would
  change behaviour on every email field on the site. See the advisory.
- **Not a complete audit.** One CVE, verified properly. That is all this claims.

## Related

- [eol-watch](https://github.com/fstivicic/eol-watch) — the scanner that finds
  advisories landing on dead branches, and the cookbook this patch followed.
- [joomla3-security-patches](https://github.com/fstivicic/joomla3-security-patches)
  — the same method applied to Joomla 3.10.

## Licence

Patches are derivative works of PrestaShop. PrestaShop core is OSL-3.0; the
patches are offered under the same terms. Tooling in `tools/` and `tests/` is
MIT.
