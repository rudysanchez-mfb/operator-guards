"""Profile/client identity and IPC socket-path resolution (plan §4, Task 13).

Resolves the runtime directory and UID at EXECUTION time (never hardcodes
``1000``), derives the per-(profile, client) IPC socket path under a
user-only ``hermes-guards`` directory, and maps a Hermes profile home to its
profile/client identity strings.

``profile_id_for`` / ``client_id_for`` mirror the ``r2d2`` plugin's
``_client_id``/``_resolve_home`` logic so the daemon and the owning client
agree on identity WITHOUT trusting any caller-supplied path: the socket path is
derived from the *resolved* runtime dir + UID + the identity pair, and a
caller-supplied path is never accepted as authority.
"""

from __future__ import annotations

import hashlib
import os
import socket

# Cap the filename component so a pathological identity cannot overflow NAME_MAX.
_MAX_NAME = 120

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


def uid() -> int:
    """The current effective UID (resolve at call time, never hardcode)."""
    return os.getuid()


def runtime_dir(env=None) -> str:
    """The per-user runtime dir: ``XDG_RUNTIME_DIR`` or ``/run/user/<uid>``."""
    environ = os.environ if env is None else env
    xdg = (environ.get("XDG_RUNTIME_DIR") or "").strip()
    if xdg:
        return xdg
    return f"/run/user/{uid()}"


def ipc_socket_dir() -> str:
    """The user-only directory holding guard IPC sockets."""
    return os.path.join(runtime_dir(), "hermes-guards")


def _safe(value: str) -> str:
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in (value or ""))
    if safe != value or not safe or safe in (".", ".."):
        safe = "s_" + hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:32]
    if len(safe) > _MAX_NAME:
        digest = hashlib.sha256((value or "").encode("utf-8")).hexdigest()
        safe = f"{safe[:_MAX_NAME - 9]}_{digest[:8]}"
    return safe


def ipc_socket_path(profile_id: str, client_id: str) -> str:
    """The IPC socket path for one owning (profile, client)."""
    return os.path.join(ipc_socket_dir(), f"{_safe(profile_id)}-{_safe(client_id)}.sock")


def profile_id_for(home: str) -> str:
    """The profile id for a Hermes home (basename, or ``default``)."""
    return os.path.basename(os.path.normpath(home or "")) or "default"


def client_id_for(home: str, host: str | None = None) -> str:
    """The client id for a Hermes home: ``<host>:<profile_id>``."""
    host = host or socket.gethostname()
    return f"{host}:{profile_id_for(home)}"


__all__ = [
    "uid",
    "runtime_dir",
    "ipc_socket_dir",
    "ipc_socket_path",
    "profile_id_for",
    "client_id_for",
]
