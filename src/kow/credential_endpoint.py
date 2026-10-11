"""The ADC credential endpoint — metadata-server shape, placeholders only (ADR-0050).

An application that authenticates as a Google service account resolves its
credential through Application Default Credentials *before* it builds a request.
If ADC finds nothing it fails without the proxy ever seeing it, so an injector
alone reaches only callers that can be handed a placeholder by hand.

This endpoint closes that gap by answering the Compute Engine metadata protocol
on loopback. The load-bearing property, and the reason it is safe to run an
unauthenticated listener at all:

    **It never returns a usable credential.** The ``access_token`` it serves is
    the binding's placeholder. A client puts it in an ``Authorization`` header,
    the request goes through the proxy, and the injector substitutes the real
    minted token on egress. A placeholder scraped off this port is inert
    anywhere else, and on-box it is still subject to the binding's destination,
    method and path policy.

Routing needs no root and no link-local address: Google's libraries honour
``GCE_METADATA_HOST`` (``google-auth`` for Python additionally reads
``GCE_METADATA_IP``, and ``gcloud`` additionally reads ``GCE_METADATA_ROOT``), so
the agent's environment gains variables next to the ones kow already sets.

Deliberately minimal: it serves the paths ADC actually probes, refuses anything
without the ``Metadata-Flavor: Google`` header exactly as the real server does,
and is a read-only view over config with no vault access and no secret material
in the process at all.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kow.config import CredentialEndpointSpec

_log = logging.getLogger("kow.credential_endpoint")

_FLAVOR_HEADER = "Metadata-Flavor"
_FLAVOR_VALUE = "Google"
_PREFIX = "/computeMetadata/v1"
# Google's own tokens start `ya29.`; some SDKs sanity-check the shape before
# using one. A placeholder that does not look like a token is a config smell we
# warn about rather than reject, since the binding's placeholder is the
# operator's to choose.
_TOKEN_PREFIX = "ya29."  # noqa: S105 # nosec B105 — a token SHAPE, not a token


class _Handler(BaseHTTPRequestHandler):
    """One request. ``spec`` is attached to the server, not the handler."""

    server_version = "Metadata Server for VM"

    # Silence BaseHTTPRequestHandler's stderr access log; we log deliberately.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        _log.debug("credential endpoint %s", format % args)

    @property
    def _spec(self) -> CredentialEndpointSpec:
        spec: CredentialEndpointSpec = self.server.spec  # type: ignore[attr-defined]
        return spec

    def do_GET(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler API)
        raw_path, _, query = self.path.partition("?")
        path = raw_path.rstrip("/") or "/"
        # The real server refuses any request without the flavor header, which
        # is what makes a browser-initiated SSRF against it useless. Mirror it.
        if self.headers.get(_FLAVOR_HEADER) != _FLAVOR_VALUE:
            self._respond(403, "Metadata-Flavor: Google header required\n")
            return
        # ``?recursive=true`` is how google-auth discovers the default service
        # account: it expects a JSON OBJECT there, and falls through to another
        # credential source if it gets a directory listing. Checked before the
        # scalar table so the query is not silently dropped (Oracle review).
        recursive = "recursive=true" in query.lower()
        if recursive:
            body = self._recursive_body(path)
            if body is not None:
                self._respond(200, body, content_type="application/json")
                return
        body = self._body_for(path)
        if body is None:
            self._respond(404, "Not Found\n")
            return
        # google-auth only JSON-decodes a response labelled application/json;
        # mislabelling the token document hands it a string where it needs a
        # mapping, and the refresh fails.
        self._respond(200, body, content_type=self._content_type_for(path))

    def _body_for(self, path: str) -> str | None:
        """The answer for one probe path, or None for 404.

        A table rather than a branch ladder: the set of paths is the contract
        with every SDK's ADC implementation, so it should be readable as a list.
        Clients address the account as ``default`` or by email, hence both keys.
        """
        spec = self._spec
        sa = f"{_PREFIX}/instance/service-accounts"
        email = spec.service_account_email
        token = json.dumps(
            {
                "access_token": spec.placeholder,
                "expires_in": spec.expires_in_seconds,
                "token_type": "Bearer",  # nosec B105 — an RFC 6750 scheme name, not a secret
            }
        )
        listing = f"default/\n{email}/\n"
        routes: dict[str, str | None] = {
            # Detection pings: an empty 200 carrying the flavor header is the
            # signal "you are on a metadata-bearing machine".
            "/": "",
            _PREFIX: "",
            f"{_PREFIX}/instance": "",
            sa: listing,
            f"{sa}/default": listing,
            f"{sa}/{email}": listing,
            f"{sa}/default/token": token,
            f"{sa}/{email}/token": token,
            f"{sa}/default/email": email,
            f"{sa}/{email}/email": email,
            f"{sa}/default/scopes": "\n".join(spec.scopes_list()) + "\n",
            f"{sa}/{email}/scopes": "\n".join(spec.scopes_list()) + "\n",
            f"{_PREFIX}/project/project-id": spec.project_id,
            f"{_PREFIX}/project/numeric-project-id": str(spec.numeric_project_id),
            # The Go SDK reads this during ADC init; serving the default keeps
            # it from falling through to a second credential source.
            f"{_PREFIX}/universe/universe-domain": "googleapis.com",
            f"{_PREFIX}/instance/id": "0",
            f"{_PREFIX}/instance/zone": "projects/0/zones/kow",
        }
        return routes.get(path)

    def _content_type_for(self, path: str) -> str:
        return "application/json" if path.endswith("/token") else "text/plain"

    def _recursive_body(self, path: str) -> str | None:
        """The JSON documents ADC asks for with ``?recursive=true``."""
        spec = self._spec
        sa = f"{_PREFIX}/instance/service-accounts"
        account = {
            "aliases": ["default"],
            "email": spec.service_account_email,
            "scopes": spec.scopes_list(),
        }
        if path in (f"{sa}/default", f"{sa}/{spec.service_account_email}"):
            return json.dumps(account)
        if path == sa:
            return json.dumps({"default": account, spec.service_account_email: account})
        return None

    def _respond(self, status: int, body: str, content_type: str = "text/plain") -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header(_FLAVOR_HEADER, _FLAVOR_VALUE)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class CredentialEndpoint:
    """Owns the listener's lifecycle. Started by the addon when config enables
    it, stopped on reload or shutdown. Threaded because ADC probes are short,
    synchronous, and concurrent across a client's startup."""

    def __init__(self, spec: CredentialEndpointSpec) -> None:
        self._spec = spec
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int | None:
        """The bound port. Reads back from the socket so port 0 (ephemeral,
        used by tests) resolves to what was actually allocated."""
        return self._server.server_address[1] if self._server else None

    def start(self) -> None:
        if self._server is not None:
            return
        if not self._spec.placeholder.startswith(_TOKEN_PREFIX):
            _log.warning(
                "credential endpoint placeholder does not start with %r; some Google "
                "SDKs validate the token shape before use. Consider prefixing the "
                "minted placeholder with %r.",
                _TOKEN_PREFIX,
                _TOKEN_PREFIX,
            )
        server = ThreadingHTTPServer((self._spec.host, self._spec.port), _Handler)
        server.spec = self._spec  # type: ignore[attr-defined]
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="kow-credential-endpoint", daemon=True
        )
        self._thread.start()
        _log.info(
            "credential endpoint serving placeholder credentials for %s on %s:%d "
            "(set GCE_METADATA_HOST / GCE_METADATA_IP in the agent environment)",
            self._spec.service_account_email,
            self._spec.host,
            self.port,
        )

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
