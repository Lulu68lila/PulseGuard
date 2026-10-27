"""PulseGuard Local REST API Server for Electron Desktop GUI."""

import json
import logging
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus
from pulseguard.engine.process_scanner import scan_running_processes
from pulseguard.engine.scanner import ScannerEngine, _default_engine
from pulseguard.engine.signatures import SignatureDatabase
from pulseguard.quarantine.manager import (
    QuarantineError,
    QuarantineManager,
    delete_quarantine,
    list_quarantine,
    quarantine_file,
    restore_file,
)
from pulseguard.watcher.fs_watcher import FileSystemWatcher

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 48201


class APIState:
    """Shared state container for the local REST API."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active_watcher: Optional[FileSystemWatcher] = None
        self.watched_path: Optional[Path] = None
        self.auto_quarantine_live: bool = False
        self.recent_events: List[Dict[str, Any]] = []

    def set_watcher(self, path: Path, auto_quarantine: bool = False) -> None:
        with self.lock:
            if self.active_watcher and self.active_watcher.is_running:
                self.active_watcher.stop()

            def on_watcher_event(res: ScanResult, q_rec: Optional[QuarantineRecord]) -> None:
                with self.lock:
                    self.recent_events.append({
                        "file_path": str(res.file_path),
                        "status": res.status.value,
                        "is_infected": res.is_infected,
                        "threat_name": res.threat.threat_name if res.threat else None,
                        "quarantine_id": q_rec.record_id if q_rec else None,
                    })
                    if len(self.recent_events) > 100:
                        self.recent_events.pop(0)

            self.watched_path = path
            self.auto_quarantine_live = auto_quarantine
            self.active_watcher = FileSystemWatcher(
                watch_paths=[path],
                auto_quarantine=auto_quarantine,
                on_event_callback=on_watcher_event,
            )
            self.active_watcher.start()

    def stop_watcher(self) -> None:
        with self.lock:
            if self.active_watcher and self.active_watcher.is_running:
                self.active_watcher.stop()
            self.active_watcher = None
            self.watched_path = None

    @property
    def is_watcher_active(self) -> bool:
        return self.active_watcher is not None and self.active_watcher.is_running


state = APIState()


class PulseGuardRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests from the Electron frontend with CORS."""

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, data: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        if path == "/api/status":
            self.handle_get_status()
        elif path == "/api/quarantine":
            self.handle_get_quarantine()
        elif path == "/api/processes":
            self.handle_get_processes(query)
        elif path == "/api/events":
            self.handle_get_events()
        else:
            self._send_json_response({"error": f"Endpoint not found: {path}"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json_response({"error": f"Invalid JSON payload: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/scan":
            self.handle_post_scan(body)
        elif path == "/api/watch/toggle":
            self.handle_post_watch_toggle(body)
        elif path == "/api/quarantine/restore":
            self.handle_post_quarantine_restore(body)
        elif path == "/api/quarantine/delete":
            self.handle_post_quarantine_delete(body)
        else:
            self._send_json_response({"error": f"Endpoint not found: {path}"}, status=HTTPStatus.NOT_FOUND)

    # --- Route Handlers ---

    def handle_get_status(self) -> None:
        db = SignatureDatabase(include_defaults=True)
        mgr = QuarantineManager()
        records = list_quarantine()
        data = {
            "engine": "ONLINE",
            "signatures": db.total_hash_signatures + db.total_byte_patterns,
            "watcher_active": state.is_watcher_active,
            "watched_path": str(state.watched_path) if state.watched_path else None,
            "quarantine_count": len(records),
            "vault_path": str(mgr.vault_dir),
        }
        self._send_json_response(data)

    def handle_post_scan(self, body: Dict[str, Any]) -> None:
        raw_path = body.get("path")
        if not raw_path:
            self._send_json_response({"error": "Missing 'path' parameter"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = Path(raw_path)
        recursive = bool(body.get("recursive", True))
        auto_q = bool(body.get("quarantine", False))

        results_list: List[Dict[str, Any]] = []
        infected_count = 0

        scan_items = [target] if target.is_file() else list(target.glob("**/*" if recursive else "*"))
        file_targets = [p for p in scan_items if p.is_file()]

        for item in file_targets:
            res = _default_engine.scan_file(item)
            is_inf = res.is_infected
            threat_name = res.threat.threat_name if res.threat else None
            q_id = None

            if is_inf:
                infected_count += 1
                if auto_q and res.threat and item.exists():
                    try:
                        q_rec = quarantine_file(item, res.threat)
                        q_id = q_rec.record_id
                    except Exception as q_exc:
                        logger.error("Failed to quarantine %s: %s", item, q_exc)

            results_list.append({
                "file_path": str(res.file_path),
                "status": res.status.value,
                "is_infected": is_inf,
                "file_hash": res.file_hash,
                "threat_name": threat_name,
                "scan_duration_ms": res.scan_duration_ms,
                "quarantine_id": q_id,
            })

        self._send_json_response({
            "results": results_list,
            "scanned_count": len(results_list),
            "infected_count": infected_count,
        })

    def handle_post_watch_toggle(self, body: Dict[str, Any]) -> None:
        activate = bool(body.get("active", False))
        watch_path_str = body.get("path")
        auto_q = bool(body.get("quarantine", False))

        if activate:
            if not watch_path_str:
                self._send_json_response({"error": "Path required to activate watcher"}, status=HTTPStatus.BAD_REQUEST)
                return
            target_dir = Path(watch_path_str)
            if not target_dir.exists() or not target_dir.is_dir():
                self._send_json_response({"error": f"Invalid directory: {watch_path_str}"}, status=HTTPStatus.BAD_REQUEST)
                return
            state.set_watcher(target_dir, auto_quarantine=auto_q)
        else:
            state.stop_watcher()

        self._send_json_response({
            "watcher_active": state.is_watcher_active,
            "watched_path": str(state.watched_path) if state.watched_path else None,
        })

    def handle_get_quarantine(self) -> None:
        records = list_quarantine()
        serialized = []
        for r in records:
            serialized.append({
                "record_id": r.record_id,
                "original_path": str(r.original_path),
                "threat_name": r.threat.threat_name,
                "severity": r.threat.severity.value,
                "quarantined_at": r.quarantined_at.isoformat(),
                "file_hash": r.file_hash,
                "is_restored": r.is_restored,
            })
        self._send_json_response({"records": serialized, "count": len(serialized)})

    def handle_post_quarantine_restore(self, body: Dict[str, Any]) -> None:
        record_id = body.get("record_id")
        dest = body.get("dest")
        if not record_id:
            self._send_json_response({"error": "Missing 'record_id' parameter"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            target_path = Path(dest) if dest else None
            restored = restore_file(record_id, destination=target_path)
            self._send_json_response({"success": True, "restored_path": str(restored)})
        except QuarantineError as exc:
            self._send_json_response({"success": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def handle_post_quarantine_delete(self, body: Dict[str, Any]) -> None:
        record_id = body.get("record_id")
        if not record_id:
            self._send_json_response({"error": "Missing 'record_id' parameter"}, status=HTTPStatus.BAD_REQUEST)
            return

        success = delete_quarantine(record_id)
        if success:
            self._send_json_response({"success": True})
        else:
            self._send_json_response({"success": False, "error": "Record not found"}, status=HTTPStatus.NOT_FOUND)

    def handle_get_processes(self, query: Optional[Dict[str, List[str]]] = None) -> None:
        limit = 30
        if query and "limit" in query:
            try:
                limit = int(query["limit"][0])
            except ValueError:
                pass

        procs_list = []
        infected_count = 0
        count = 0
        for p in scan_running_processes():
            if p.is_infected:
                infected_count += 1
            procs_list.append({
                "pid": p.pid,
                "name": p.name,
                "exe_path": str(p.exe_path) if p.exe_path else None,
                "is_infected": p.is_infected,
                "threat_name": p.threat.threat_name if p.threat else None,
            })
            count += 1
            if count >= limit:
                break

        self._send_json_response({
            "processes": procs_list,
            "scanned_count": len(procs_list),
            "infected_count": infected_count,
        })

    def handle_get_events(self) -> None:
        with state.lock:
            self._send_json_response({"events": list(state.recent_events)})

    def log_message(self, format: str, *args: Any) -> None:
        pass


class PulseGuardAPIServer:
    """Manages the lifecycle of the local REST API server."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, block: bool = False) -> None:
        self.server = ThreadingHTTPServer((self.host, self.port), PulseGuardRequestHandler)
        logger.info("PulseGuard API server running on http://%s:%d", self.host, self.port)

        if block:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        state.stop_watcher()
        logger.info("PulseGuard API server stopped.")
