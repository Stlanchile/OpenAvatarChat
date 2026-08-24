"""Session-local normal-application admission authority."""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NormalModeIsolationSnapshotV1:
    admission_open: bool
    transport_keepalive_allowed: bool
    destroyed: bool
    revision: int
    close_count: int
    reopen_count: int


class NormalApplicationAdmissionViewV1:
    """Read-only mode gate shared with core application-work admission."""

    __slots__ = ("__authority",)

    def __init__(self, authority: _NormalModeIsolationAuthorityV1) -> None:
        self.__authority = authority

    def is_open_v1(self) -> bool:
        return self.__authority._is_open_v1()

    def snapshot_v1(self) -> NormalModeIsolationSnapshotV1:
        return self.__authority._snapshot_v1()

    def transport_keepalive_is_allowed_v1(self) -> bool:
        return self.__authority._transport_keepalive_is_allowed_v1()

    def __repr__(self) -> str:
        return "NormalApplicationAdmissionViewV1(<opaque>)"


class _NormalModeIsolationControllerV1:
    """Unexported mutation authority held only by CaptureCoordinatorV1."""

    __slots__ = ("__authority", "__owner")

    def __init__(
        self,
        authority: _NormalModeIsolationAuthorityV1,
        owner: object,
    ) -> None:
        self.__authority = authority
        self.__owner = owner

    def close_v1(self) -> bool:
        return self.__authority._close_v1(self.__owner)

    def reopen_v1(self) -> bool:
        return self.__authority._reopen_v1(self.__owner)

    def disable_transport_keepalive_v1(self) -> None:
        self.__authority._disable_transport_keepalive_v1(self.__owner)

    def destroy_v1(self) -> None:
        self.__authority._destroy_v1(self.__owner)

    def snapshot_v1(self) -> NormalModeIsolationSnapshotV1:
        return self.__authority._snapshot_v1()

    def __repr__(self) -> str:
        return "_NormalModeIsolationControllerV1(<opaque>)"


class _NormalModeIsolationAuthorityV1:
    __slots__ = (
        "_admission_open",
        "_close_count",
        "_destroyed",
        "_lock",
        "_owner",
        "_reopen_count",
        "_revision",
        "_transport_keepalive_allowed",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._admission_open = True
        self._transport_keepalive_allowed = True
        self._destroyed = False
        self._revision = 0
        self._close_count = 0
        self._reopen_count = 0
        self._owner = object()

    @classmethod
    def create_v1(
        cls,
    ) -> tuple[
        _NormalModeIsolationControllerV1,
        NormalApplicationAdmissionViewV1,
    ]:
        authority = cls()
        return (
            _NormalModeIsolationControllerV1(
                authority,
                authority._owner,
            ),
            NormalApplicationAdmissionViewV1(authority),
        )

    def _owner_matches_v1(self, owner: object) -> bool:
        return owner is self._owner

    def _is_open_v1(self) -> bool:
        with self._lock:
            return self._admission_open and not self._destroyed

    def _transport_keepalive_is_allowed_v1(self) -> bool:
        with self._lock:
            return self._transport_keepalive_allowed and not self._destroyed

    def _close_v1(self, owner: object) -> bool:
        with self._lock:
            if (
                not self._owner_matches_v1(owner)
                or self._destroyed
                or not self._admission_open
            ):
                return False
            self._admission_open = False
            self._revision += 1
            self._close_count += 1
            return True

    def _reopen_v1(self, owner: object) -> bool:
        with self._lock:
            if (
                not self._owner_matches_v1(owner)
                or self._destroyed
                or self._admission_open
            ):
                return False
            self._admission_open = True
            self._transport_keepalive_allowed = True
            self._revision += 1
            self._reopen_count += 1
            return True

    def _disable_transport_keepalive_v1(self, owner: object) -> None:
        with self._lock:
            if (
                not self._owner_matches_v1(owner)
                or self._destroyed
                or not self._transport_keepalive_allowed
            ):
                return
            self._transport_keepalive_allowed = False
            self._revision += 1

    def _destroy_v1(self, owner: object) -> None:
        with self._lock:
            if not self._owner_matches_v1(owner):
                return
            self._admission_open = False
            self._transport_keepalive_allowed = False
            self._destroyed = True
            self._revision += 1
            self._owner = object()

    def _snapshot_v1(self) -> NormalModeIsolationSnapshotV1:
        with self._lock:
            return NormalModeIsolationSnapshotV1(
                admission_open=(self._admission_open and not self._destroyed),
                transport_keepalive_allowed=(
                    self._transport_keepalive_allowed and not self._destroyed
                ),
                destroyed=self._destroyed,
                revision=self._revision,
                close_count=self._close_count,
                reopen_count=self._reopen_count,
            )


def _create_normal_mode_isolation_v1() -> tuple[
    _NormalModeIsolationControllerV1,
    NormalApplicationAdmissionViewV1,
]:
    return _NormalModeIsolationAuthorityV1.create_v1()


__all__ = [
    "NormalApplicationAdmissionViewV1",
    "NormalModeIsolationSnapshotV1",
]
