"""PulseGuard Real-Time Filesystem Watcher Subsystem."""

from pulseguard.watcher.fs_watcher import (
    DEFAULT_DEBOUNCE_SECONDS,
    DEFAULT_IGNORED_EXTENSIONS,
    DEFAULT_IGNORED_PATTERNS,
    FileSystemWatcher,
    PulseGuardEventHandler,
)

__all__ = [
    "DEFAULT_DEBOUNCE_SECONDS",
    "DEFAULT_IGNORED_EXTENSIONS",
    "DEFAULT_IGNORED_PATTERNS",
    "FileSystemWatcher",
    "PulseGuardEventHandler",
]
