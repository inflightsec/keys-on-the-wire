#!/usr/bin/env python3
"""A fake ``kow-keyd`` — enough of it to test the helper transmit path (ADR-0051).

Same reasoning as ``_fake_security.py``: the interesting failure modes of a
subprocess wrapper live in the process boundary itself, so this is a real
executable rather than a monkeypatched ``subprocess.run``. argv, stdin, stdout
bytes and the exit-code contract are all genuinely exercised — on Linux, where
the code is written.

It implements the contract from ``helper/kow-keyd.c``'s header, including the
post-ADR-0051 shape: ``set`` updates in place when the item exists and only adds
when it does not, so there is no window where the credential is absent.

It is NOT a keychain. There are no ACLs and no crypto. The one ACL behaviour it
can usefully model is "this item was written by something else and the helper
cannot read it", which is what ``FAKE_KEYD_FAIL=interaction`` is for. The real
helper against a real keychain is covered by ``tests/vm-e2e/macos-keyd-e2e.sh``.

Driven by the environment:

    FAKE_KEYD_STORE     path to the JSON item store (required)
    FAKE_KEYD_ARGV_LOG  path; one JSON argv list appended per invocation
    FAKE_KEYD_STDIN_LOG path; the raw bytes handed to `set`/`replace`
    FAKE_KEYD_FAIL      interaction | entitlement | notfound | boom | usage
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_MISSING_ENTITLEMENT = 34
EXIT_NOT_FOUND = 44
EXIT_INTERACTION = 51

_FAIL_MODES = {
    "interaction": (EXIT_INTERACTION, "kow-keyd: read failed (-25308): interaction is not allowed"),
    "entitlement": (
        EXIT_MISSING_ENTITLEMENT,
        "kow-keyd: write failed (-34018): missing entitlement",
    ),
    "notfound": (EXIT_NOT_FOUND, "kow-keyd: read failed (-25300): item not found"),
    "boom": (EXIT_FAIL, "kow-keyd: something went wrong"),
    "usage": (EXIT_USAGE, "kow-keyd: --service is required"),
}


def _store() -> Path:
    return Path(os.environ["FAKE_KEYD_STORE"])


def _load() -> list[dict[str, str]]:
    p = _store()
    if not p.exists():
        return []
    items: list[dict[str, str]] = json.loads(p.read_text() or "[]")
    return items


def _save(items: list[dict[str, str]]) -> None:
    _store().write_text(json.dumps(items))


def _parse(argv: list[str]) -> tuple[str, dict[str, str]]:
    if not argv:
        return "", {}
    verb, rest = argv[0], argv[1:]
    opts: dict[str, str] = {}
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("--service", "--account", "--keychain", "--access-group") and i + 1 < len(rest):
            opts[tok.lstrip("-")] = rest[i + 1]
            i += 2
        elif tok == "--data-protection":
            opts["data-protection"] = ""
            i += 1
        else:
            return verb, {"__bad__": tok}
    return verb, opts


def _matches(items: list[dict[str, str]], opts: dict[str, str]) -> list[dict[str, str]]:
    svce, acct = opts.get("service", ""), opts.get("account")
    return [i for i in items if i["svce"] == svce and (acct is None or i["acct"] == acct)]


def _dispatch(verb: str, opts: dict[str, str]) -> int:  # noqa: C901 — flat verb table
    if "__bad__" in opts:
        print(f"kow-keyd: unknown argument {opts['__bad__']}", file=sys.stderr)
        return EXIT_USAGE
    if not opts.get("service"):
        print("kow-keyd: --service is required", file=sys.stderr)
        return EXIT_USAGE
    if verb != "list" and not opts.get("account"):
        print(f"kow-keyd: --account is required for {verb}", file=sys.stderr)
        return EXIT_USAGE

    items = _load()
    found = _matches(items, opts)

    if verb == "get":
        if not found:
            print("kow-keyd: read failed (-25300): item not found", file=sys.stderr)
            return EXIT_NOT_FOUND
        # Raw bytes, no trailing newline — the real helper's contract.
        sys.stdout.buffer.write(found[0]["value"].encode("utf-8", "surrogateescape"))
        return 0

    if verb in ("set", "replace"):
        raw = sys.stdin.buffer.read()
        log = os.environ.get("FAKE_KEYD_STDIN_LOG")
        if log:
            Path(log).write_bytes(raw)
        value = raw.decode("utf-8", "surrogateescape")
        if verb == "replace":
            # Delete-then-add. Only reachable through the migration path.
            for it in found:
                items.remove(it)
            found = []
        if found:
            # Update in place: no window where the credential is absent.
            found[0]["value"] = value
        else:
            items.append({"svce": opts["service"], "acct": opts["account"], "value": value})
        _save(items)
        return 0

    if verb == "delete":
        if not found:
            return 0  # idempotent
        for it in found:
            items.remove(it)
        _save(items)
        return 0

    if verb == "list":
        # One line per match, NOT deduplicated: the duplicate check counts these.
        for it in found:
            sys.stdout.write(it["acct"] + "\n")
        return 0

    print(f"kow-keyd: unknown verb {verb}", file=sys.stderr)
    return EXIT_USAGE


def main() -> int:
    argv = sys.argv[1:]
    log = os.environ.get("FAKE_KEYD_ARGV_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(json.dumps(argv) + "\n")

    verb, opts = _parse(argv)

    fail = os.environ.get("FAKE_KEYD_FAIL", "")
    # `<verb>:<mode>` fails only that verb. Without it, "the duplicate check
    # fails open" is untestable: a blanket failure also breaks the read that
    # follows, so the write is refused either way and the assertion passes for
    # the wrong reason. Mutation testing found exactly that.
    if ":" in fail:
        only_verb, _, fail = fail.partition(":")
        if only_verb != verb:
            fail = ""
    if fail in _FAIL_MODES:
        code, message = _FAIL_MODES[fail]
        print(message, file=sys.stderr)
        return code

    return _dispatch(verb, opts)


if __name__ == "__main__":
    raise SystemExit(main())
