"""Denial taxonomy — every refusal the agent can see, in one place.

``client_message`` crosses the wire. Agents and operators grep it, so it is
byte-stable and pinned by ``tests/test_denials.py``; changing one is a
compatibility change, not a tidy-up. ``operator_detail`` never leaves the box.

Audit reasons are NOT here. They stay at the call site and keep their existing
strings (docs/architecture.md 4.4) — the wire text and the audit vocabulary are
deliberately separate surfaces.
"""

from __future__ import annotations

from typing import Any


class DenialError(Exception):
    """Base. Subclasses set the wire-visible ``client_message``."""

    client_message: bytes = b"kow: request denied\n"

    def __init__(self, operator_detail: str = "") -> None:
        super().__init__(operator_detail)
        self.operator_detail = operator_detail


# --- routing / policy -------------------------------------------------------


class SniHostMismatchError(DenialError):
    client_message = b"kow: CONNECT host and request host disagree\n"


class DestinationNotBoundError(DenialError):
    client_message = b"kow: destination not in any binding\n"


class AmbiguousPlaceholderError(DenialError):
    client_message = b"kow: ambiguous placeholder match\n"


class HeaderControlCharactersError(DenialError):
    client_message = b"kow: header value contains control characters\n"


# --- single-secret resolution ----------------------------------------------


class SecretUnavailableError(DenialError):
    client_message = b"kow: secret unavailable\n"


class SecretFetchFailedError(DenialError):
    client_message = b"kow: secret fetch failed\n"


# --- composite --------------------------------------------------------------


class CompositeUnavailableError(DenialError):
    client_message = b"kow: composite secret unavailable\n"


class CompositeFetchFailedError(DenialError):
    client_message = b"kow: composite secret fetch failed\n"


class CompositeRenderFailedError(DenialError):
    client_message = b"kow: composite render failed\n"


class CompositeRenderUnexpectedError(DenialError):
    client_message = b"kow: composite render failed unexpectedly\n"


# --- signing ----------------------------------------------------------------


class SigningStateUnavailableError(DenialError):
    client_message = b"kow: signing state unavailable\n"


class UnrecognizedSigningInjectorError(DenialError):
    client_message = b"kow: unrecognized signing injector\n"


class SigningKeyUnavailableError(DenialError):
    client_message = b"kow: signing key unavailable\n"


class Sigv4CredentialUnavailableError(DenialError):
    client_message = b"kow: sigv4 credential unavailable\n"


# --- token exchange ---------------------------------------------------------


class ExchangeFailedError(DenialError):
    """A token endpoint returned a non-success outcome.

    Folds the three near-identical sentinels the injectors each defined. Carries
    the categorised result so the leader can audit the outcome without re-running
    the exchange; the dedup machinery propagates it to every waiter.
    """

    def __init__(self, result: Any, operator_detail: str = "") -> None:
        super().__init__(operator_detail)
        self.result = result


class OauthExchangeFailedError(ExchangeFailedError):
    client_message = b"kow: oauth2 token exchange failed\n"


class OauthCcExchangeFailedError(ExchangeFailedError):
    client_message = b"kow: oauth2 client-credentials exchange failed\n"


class GithubAppExchangeFailedError(ExchangeFailedError):
    client_message = b"kow: github app token exchange failed\n"


class GcpMintFailedError(ExchangeFailedError):
    """ADR-0050: any mint failure, in any of the three modes — a rejected
    assertion, an unreachable token endpoint, a refused impersonation, or an
    absent source identity. One wire message for all of them: the client learns
    that kow could not mint, never which leg failed."""

    client_message = b"kow: gcp service-account token mint failed\n"


class GcpKeyUnavailableError(DenialError):
    client_message = b"kow: gcp service-account key unavailable\n"


class OauthInputUnavailableError(DenialError):
    client_message = b"kow: oauth2 input secret unavailable\n"


class OauthInputFetchFailedError(DenialError):
    client_message = b"kow: oauth2 input secret fetch failed\n"


class OauthCcSecretUnavailableError(DenialError):
    client_message = b"kow: oauth2 client-credentials secret unavailable\n"


class GithubAppKeyUnavailableError(DenialError):
    client_message = b"kow: github app private key unavailable\n"
