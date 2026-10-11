"""``kow binding`` — generate a paste-ready binding note/annotation.

Deterministic authoring of the per-secret binding metadata (BWS ``notes`` field
or GSM ``avp-binding`` annotation). The tool builds the note from flags and
**validates it through the daemon's own** ``parse_notes_binding`` **parser
before printing it**, so it can only ever emit a binding the daemon will
accept — the mandatory ``# avp-binding`` marker present, the ``{secret}`` token
present, a valid host.

This is the code-before-prompts backbone the ``kow`` skill wraps: the
security-critical note is produced by code, not authored free-hand by an LLM.
Two real outages came from hand-authored notes — a missing marker (2026-07-18,
silent fleet un-brokering) and a host-shaped description mistaken for a host —
both structurally impossible to emit from this tool.
"""

from __future__ import annotations

import argparse
import sys

from kow.notes_binding import (
    NOTES_MARKER,
    InvalidBinding,
    ParsedBinding,
    parse_notes_binding,
)
from kow.placeholders import PLACEHOLDER_PREFIX, mint_placeholder

# The generic substitution token the note carries (the parser rewrites it to
# ``{<secret_name>}``). Kept in sync with notes_binding by contract.
_SECRET_TOKEN = "{secret}"  # noqa: S105  # nosec B105 — public template slot, not a credential

# Any non-empty placeholder validates; it is only stamped into the SecretSpec
# during self-validation (never emitted). Built from the prefix constant so it
# tracks the format automatically and stays regex-valid.
_VALIDATE_PLACEHOLDER = PLACEHOLDER_PREFIX + "bindingnewvalidatesentinel"


def _die(msg: str) -> int:
    print(f"kow binding: {msg}", file=sys.stderr)
    return 1


def _build_note(
    *,
    hosts: list[str],
    header: str,
    fmt: str,
    methods: list[str],
    paths: list[str],
    placeholder: str | None = None,
) -> str:
    """Build the flat-YAML note, marker first, in the canonical field order."""
    lines = [NOTES_MARKER]
    if len(hosts) == 1:
        lines.append(f"host: {hosts[0]}")
    else:
        lines.append("host: [" + ", ".join(hosts) + "]")
    if placeholder is not None:
        lines.append(f"placeholder: {placeholder}")
    lines.append(f"header: {header}")
    lines.append(f'format: "{fmt}"')
    if methods:
        lines.append("methods: [" + ", ".join(methods) + "]")
    if paths:
        lines.append("paths: [" + ", ".join(f'"{p}"' for p in paths) + "]")
    return "\n".join(lines) + "\n"


def _gsm_command(name: str, note: str) -> str:
    """Render the gcloud annotation-update command, printf-embedding the note so
    the multi-line YAML survives as a single shell argument (matches the
    kow skill's GSM example)."""
    embedded = note.rstrip("\n").replace('"', '\\"').replace("\n", "\\n")
    return (
        f"gcloud secrets update {name} --update-annotations=\"kow-binding=$(printf '{embedded}')\""
    )


# --- gcp service accounts (ADR-0050) ----------------------------------------

# A notes binding can only express the plain header injector (notes_binding.py
# hardcodes `type: header`), and that is deliberate: ADR-0024 keeps vault-side
# metadata able to NARROW scope only, never to declare a new minting binding.
# So a Google service-account binding lives in bindings.yaml, and this tool's
# job is to make that as close to one command as the notes flow is.
_GOOGLE_SCOPE_PREFIX = "https://www.googleapis.com/auth/"
# Google's own access tokens start `ya29.`; some SDKs check the shape before
# using one, and the credential endpoint hands this string to real clients.
_GCP_PLACEHOLDER_PREFIX = "ya29."  # noqa: S105 — a token SHAPE, not a token


def _expand_scopes(raw: list[str]) -> str:
    """`bigquery.readonly` -> the full scope URL; full URLs pass through."""
    return " ".join(s if "://" in s else _GOOGLE_SCOPE_PREFIX + s for s in raw)


def _gcp_yaml(args: argparse.Namespace, placeholder: str, scopes: str) -> str:
    """The bindings.yaml block. Built as text (not yaml.dump) so the comments
    that explain the security posture survive into the operator's file."""
    methods = [m.strip() for m in args.methods.split(",") if m.strip()] if args.methods else []
    paths = [p.strip() for p in args.paths.split(",") if p.strip()] if args.paths else []
    lines = [
        f"  {args.name}:",
        f'    placeholder: "{placeholder}"',
        "    inject:",
        "      type: gcp_service_account",
        f"      mode: {args.mode}",
        f"      service_account_email: {args.target}",
        f'      scopes: "{scopes}"',
    ]
    if args.mode == "impersonate":
        lines.append(f"      source: {args.source}")
        if args.source == "seat_key":
            lines.append(f"      source_service_account_email: {args.seat}")
            lines.append(f"      private_key_secret: {args.key_secret}")
    else:
        lines.append(f"      private_key_secret: {args.key_secret}")
        if args.mode == "self_signed_jwt" and args.audience:
            lines.append(f'      audience: "{args.audience}"')
    lines.append("    bindings:")
    for host in args.host:
        lines.append(f'      - host: "{host}"')
        if methods:
            lines.append("        methods: [" + ", ".join(methods) + "]")
        if paths:
            lines.append("        paths: [" + ", ".join(f'"{p}"' for p in paths) + "]")
    block = "\n".join(lines) + "\n"
    if args.no_endpoint:
        return block
    endpoint = [
        "",
        "credential_endpoint:",
        "  enabled: true",
        f"  port: {args.endpoint_port}",
        f"  binding: {args.name}",
        f"  service_account_email: {args.target}",
        f'  scopes: "{scopes}"',
    ]
    if args.project:
        endpoint.append(f"  project_id: {args.project}")
    return block + "\n".join(endpoint) + "\n"


def _validate_gcp(args: argparse.Namespace, block: str) -> str | None:
    """Parse the generated YAML through the daemon's own Config model. Returns
    a diagnostic string on failure, None when the daemon would accept it."""
    import yaml

    from kow.config import Config

    doc = yaml.safe_load(
        "version: 1\nbinding_source: file\naudit:\n  path: /tmp/kow-validate.jsonl\nsecrets:\n"
        + block
    )
    try:
        Config.model_validate(doc)
    except Exception as e:  # noqa: BLE001 — any rejection is a refusal to print
        return str(e)
    return None


def _run_binding_gcp(args: argparse.Namespace) -> int:
    if args.mode != "impersonate" and not args.key_secret:
        return _die(
            f"--key-secret is required in {args.mode} mode (the vault entry holding the PEM)."
        )
    if (
        args.mode == "impersonate"
        and args.source == "seat_key"
        and not (args.seat and args.key_secret)
    ):
        return _die("--source seat_key requires --seat and --key-secret.")
    if args.mode == "impersonate" and args.source == "adc" and args.key_secret:
        return _die("--key-secret is meaningless with --source adc; use --source seat_key.")

    placeholder = _GCP_PLACEHOLDER_PREFIX + mint_placeholder()
    scopes = _expand_scopes(args.scope)
    block = _gcp_yaml(args, placeholder, scopes)

    diagnostic = _validate_gcp(args, block)
    if diagnostic is not None:
        return _die(f"generated binding is invalid: {diagnostic}")

    print(block, end="")

    wiring = [
        "kow binding: paste the block above into bindings.yaml, then reload the daemon.",
    ]
    if args.mode != "impersonate" or args.source == "seat_key":
        wiring.append(
            f"kow binding: store the service-account PEM in the vault as "
            f"{args.key_secret!r} (the `private_key` value from the key JSON, not the whole file)."
        )
    else:
        wiring.append(
            "kow binding: no key to store — the daemon impersonates with its own "
            "credentials. Grant it roles/iam.serviceAccountTokenCreator on "
            f"{args.target}."
        )
    if args.no_endpoint:
        wiring.append(
            f"kow binding: wire the consumer — export {args.name}='{placeholder}' and have "
            "the app send it as the Authorization bearer token."
        )
    else:
        wiring.append(
            "kow binding: wire the consumer — the app needs NO code change, only these "
            "environment variables:\n"
            f"  export GCE_METADATA_HOST=127.0.0.1:{args.endpoint_port}\n"
            f"  export GCE_METADATA_IP=127.0.0.1:{args.endpoint_port}     # python only\n"
            f"  export GCE_METADATA_ROOT=127.0.0.1:{args.endpoint_port}   # gcloud only\n"
            "  export HTTPS_PROXY=http://127.0.0.1:14322"
        )
    print("\n".join(wiring), file=sys.stderr)
    return 0


def run_binding(args: argparse.Namespace) -> int:
    subcommand = getattr(args, "binding_cmd", None)
    if subcommand == "gcp":
        return _run_binding_gcp(args)
    if subcommand != "new":
        return _die("unknown subcommand; use `kow binding new --host <host>` or `kow binding gcp`.")

    fmt: str = args.format
    if _SECRET_TOKEN not in fmt:
        return _die(
            f"--format must contain the {_SECRET_TOKEN} token "
            f'(e.g. "Bearer {_SECRET_TOKEN}"); got {fmt!r}.'
        )

    methods = [m.strip() for m in args.methods.split(",") if m.strip()] if args.methods else []
    paths = [p.strip() for p in args.paths.split(",") if p.strip()] if args.paths else []

    # ADR-0029: mint a stored placeholder by default so the note itself pins
    # what the consumer must emit — no salt, no sudo `kow env` discovery.
    # `--no-placeholder` keeps the legacy salt-derived flow.
    minted = None if getattr(args, "no_placeholder", False) else mint_placeholder()

    note = _build_note(
        hosts=args.host,
        header=args.header,
        fmt=fmt,
        methods=methods,
        paths=paths,
        placeholder=minted,
    )

    # Self-validate against the REAL parser: refuse to print anything the daemon
    # would reject. This is the entire point of the tool.
    result = parse_notes_binding(
        secret_name=args.name, placeholder=_VALIDATE_PLACEHOLDER, note=note
    )
    if isinstance(result, InvalidBinding):
        return _die(f"generated binding is invalid: {result.diagnostic}")
    if not isinstance(result, ParsedBinding):
        return _die(
            "generated note did not resolve to a binding (no usable host). "
            "Pass at least one valid --host (dot-separated DNS labels)."
        )

    if args.backend == "gsm":
        print(_gsm_command(args.name, note))
    else:
        print(note, end="")
    if minted is not None:
        # Wiring hint on stderr (stdout stays a pure paste artifact): the
        # placeholder is a sentinel, not a secret — safe to print and to
        # write into the consumer's env/config.
        print(
            "kow binding: wire the consumer now — add this line to the "
            f"calling app's env:\n  export {args.name}='{minted}'\n"
            "kow binding: the daemon picks the note up on its next reload.",
            file=sys.stderr,
        )
    return 0


def register_binding_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    binding_p = parent_subparsers.add_parser(
        "binding",
        help="Generate a paste-ready binding note/annotation for a secret.",
        description=(
            "Author the per-secret binding metadata deterministically. The note is "
            "validated through the daemon's own parser before it is printed, so it "
            "always carries the mandatory marker, the {secret} token, and a valid host."
        ),
    )
    binding_sub = binding_p.add_subparsers(dest="binding_cmd")
    new_p = binding_sub.add_parser(
        "new",
        help="Print the binding note (BWS) or annotation command (GSM) to paste.",
        description=(
            "Build and validate a binding, then print the exact artifact to paste "
            "into the secret's BWS Notes field (default) or run for a GSM annotation. "
            "Prints nothing and exits non-zero if the binding would not parse."
        ),
    )
    gcp_p = binding_sub.add_parser(
        "gcp",
        help="Print the bindings.yaml block for a Google service account (ADR-0050).",
        description=(
            "Build and validate a gcp_service_account binding, then print the exact "
            "block to paste into bindings.yaml plus the consumer wiring. A notes "
            "binding cannot express a minting injector (ADR-0024 keeps vault-side "
            "metadata scope-narrowing only), so this binding lives in the config file "
            "and this tool is what keeps that one command instead of hand-authoring."
        ),
    )
    gcp_p.add_argument(
        "--target",
        required=True,
        metavar="EMAIL",
        help="The service account the app should act as.",
    )
    gcp_p.add_argument(
        "--host",
        action="append",
        required=True,
        metavar="HOST",
        help="Google API host the credential may be sent to (e.g. bigquery.googleapis.com).",
    )
    gcp_p.add_argument(
        "--scope",
        action="append",
        required=True,
        metavar="SCOPE",
        help="OAuth scope; a bare name like 'bigquery.readonly' is expanded. Repeatable.",
    )
    gcp_p.add_argument(
        "--name",
        default="GCP",
        help="Binding name, used as the config key (default: GCP).",
    )
    gcp_p.add_argument(
        "--mode",
        choices=("impersonate", "jwt_bearer_grant", "self_signed_jwt"),
        default="impersonate",
        help="Mint mode (default: impersonate — no service-account key exists).",
    )
    gcp_p.add_argument(
        "--source",
        choices=("adc", "seat_key"),
        default="adc",
        help="impersonate only: mint with the daemon's own credentials, or a vault-held seat.",
    )
    gcp_p.add_argument(
        "--seat", default=None, metavar="EMAIL", help="The impersonation seat's email."
    )
    gcp_p.add_argument(
        "--key-secret",
        default=None,
        metavar="NAME",
        help="Vault entry holding the PEM private key (key-bearing modes / seat_key).",
    )
    gcp_p.add_argument(
        "--audience", default=None, help="self_signed_jwt only: the target service endpoint."
    )
    gcp_p.add_argument("--methods", default=None, help="Comma-separated methods to scope to.")
    gcp_p.add_argument("--paths", default=None, help="Comma-separated path globs to scope to.")
    gcp_p.add_argument(
        "--project", default=None, help="Project id served by the credential endpoint."
    )
    gcp_p.add_argument(
        "--endpoint-port",
        type=int,
        default=14380,
        help="Credential endpoint port (default: 14380).",
    )
    gcp_p.add_argument(
        "--no-endpoint",
        action="store_true",
        help=(
            "Omit the ADC credential endpoint. The consumer must then present the "
            "placeholder itself, which only suits hand-rolled REST callers."
        ),
    )
    new_p.add_argument(
        "--host",
        action="append",
        required=True,
        metavar="HOST",
        help="Destination hostname the credential is sent to. Repeat for multi-host.",
    )
    new_p.add_argument(
        "--header",
        default="Authorization",
        help="HTTP header to inject into (default: Authorization).",
    )
    new_p.add_argument(
        "--format",
        default="Bearer {secret}",
        help='Header value template; MUST contain {secret} (default: "Bearer {secret}").',
    )
    new_p.add_argument(
        "--methods",
        default=None,
        help="Comma-separated HTTP methods to scope the binding to (default: all).",
    )
    new_p.add_argument(
        "--paths",
        default=None,
        help="Comma-separated URL path globs to scope the binding to (default: all).",
    )
    new_p.add_argument(
        "--name",
        default="SECRET",
        help="Secret name — used for the GSM command and the {secret} token rewrite.",
    )
    new_p.add_argument(
        "--backend",
        choices=("bws", "gsm"),
        default="bws",
        help="Output style: bws notes block (default) or gsm gcloud command.",
    )
    new_p.add_argument(
        "--no-placeholder",
        action="store_true",
        help=(
            "Do not mint a stored placeholder into the note; the daemon then "
            "derives one from the install salt (legacy flow — the consumer "
            "must discover it via `kow env` on the daemon host)."
        ),
    )
