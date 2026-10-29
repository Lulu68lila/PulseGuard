"""PulseGuard Local REST API Server for Electron Desktop GUI."""

import json
import logging
import os
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus, ThreatSeverity
from pulseguard.engine.ai_scanner import NemotronAIScanner
from pulseguard.engine.process_scanner import scan_running_processes
from pulseguard.engine.scanner import ScannerEngine, _default_engine
from pulseguard.engine.signatures import SignatureDatabase
from pulseguard.engine.vulnerability_scanner import VulnerabilityScanner
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

EXCLUDED_SCAN_PARTS = {
    ".git", ".svn", ".hg", "node_modules", "target", ".cargo",
    ".rustup", ".venv", "venv", "__pycache__", ".pgvault",
    "incremental", "AppData",
}

_default_ai_scanner = NemotronAIScanner()
_default_vuln_scanner = VulnerabilityScanner()


class ActiveScanTask:
    """Manages real-time asynchronous file scanning with live progress reporting."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.is_running: bool = False
        self.should_stop: bool = False
        self.scan_type: str = "custom"
        self.current_file: str = ""
        self.scanned_count: int = 0
        self.infected_count: int = 0
        self.quarantined_count: int = 0
        self.total_target_files: int = 0
        self.progress_percent: int = 0
        self.start_time: float = 0.0
        self.elapsed_seconds: float = 0.0
        self.results: List[Dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None

    def start_scan(
        self,
        paths: List[Path],
        scan_type: str = "custom",
        recursive: bool = True,
        auto_quarantine: bool = False,
    ) -> None:
        with self.lock:
            if self.is_running:
                self.should_stop = True
                if self._thread and self._thread.is_alive():
                    self._thread.join(timeout=1.0)
            self.is_running = True
            self.should_stop = False
            self.scan_type = scan_type
            self.current_file = "Recherche des fichiers..."
            self.scanned_count = 0
            self.infected_count = 0
            self.quarantined_count = 0
            self.progress_percent = 0
            self.start_time = time.time()
            self.elapsed_seconds = 0.0
            self.results = []

        def worker() -> None:
            file_targets: List[Path] = []
            for p in paths:
                if self.should_stop:
                    break
                if p.is_file():
                    file_targets.append(p)
                elif p.is_dir():
                    try:
                        if scan_type == "quick":
                            # Fast scan: only shallow depth in user directories, skipping heavy caches
                            for entry in p.iterdir():
                                if self.should_stop:
                                    break
                                if entry.name in EXCLUDED_SCAN_PARTS:
                                    continue
                                if entry.is_file():
                                    file_targets.append(entry)
                                elif entry.is_dir():
                                    for subentry in entry.iterdir():
                                        if subentry.is_file():
                                            file_targets.append(subentry)
                                            if len(file_targets) >= 400:
                                                break
                        else:
                            scan_glob = p.glob("**/*" if recursive else "*")
                            for sub in scan_glob:
                                if self.should_stop:
                                    break
                                # Skip build artifacts and system internal caches
                                if any(part in EXCLUDED_SCAN_PARTS for part in sub.parts):
                                    continue
                                if sub.is_file():
                                    file_targets.append(sub)
                                    if len(file_targets) >= 2500:
                                        break
                    except Exception as err:
                        logger.debug("Glob error on %s: %s", p, err)

            with self.lock:
                self.total_target_files = max(len(file_targets), 1)

            for idx, item in enumerate(file_targets):
                if self.should_stop:
                    break
                with self.lock:
                    self.current_file = str(item)
                    self.elapsed_seconds = time.time() - self.start_time
                    self.progress_percent = min(int((idx / self.total_target_files) * 100), 99)

                res = _default_engine.scan_file(item)
                is_inf = res.is_infected
                threat_name = res.threat.threat_name if res.threat else None
                q_id = None

                if is_inf:
                    with self.lock:
                        self.infected_count += 1
                    # Robust security: Only auto-quarantine verified CRITICAL / HIGH threats
                    if (
                        auto_quarantine
                        and res.threat
                        and res.threat.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
                        and item.exists()
                    ):
                        try:
                            q_rec = quarantine_file(item, res.threat)
                            q_id = q_rec.record_id
                            with self.lock:
                                self.quarantined_count += 1
                        except Exception as q_exc:
                            logger.error("Failed to quarantine %s: %s", item, q_exc)

                with self.lock:
                    self.scanned_count += 1
                    self.results.append({
                        "file_path": str(res.file_path),
                        "status": res.status.value,
                        "is_infected": is_inf,
                        "file_hash": res.file_hash,
                        "threat_name": threat_name,
                        "severity": res.threat.severity.value if res.threat else None,
                        "scan_duration_ms": res.scan_duration_ms,
                        "quarantine_id": q_id,
                    })

            with self.lock:
                self.progress_percent = 100
                self.elapsed_seconds = time.time() - self.start_time
                self.is_running = False
                self.current_file = "Analyse terminée."

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def stop_scan(self) -> None:
        with self.lock:
            self.should_stop = True
            self.is_running = False

    def get_progress(self) -> Dict[str, Any]:
        with self.lock:
            elapsed = time.time() - self.start_time if self.is_running else self.elapsed_seconds
            return {
                "running": self.is_running,
                "scan_type": self.scan_type,
                "current_file": self.current_file,
                "scanned_count": self.scanned_count,
                "infected_count": self.infected_count,
                "quarantined_count": self.quarantined_count,
                "progress_percent": self.progress_percent,
                "elapsed_seconds": round(elapsed, 1),
                "results": list(self.results),
            }


class APIState:
    """Shared state container for the local REST API."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.watcher: Optional[FileSystemWatcher] = None
        self.watched_path: Optional[Path] = None
        self.auto_quarantine_live: bool = False
        self.recent_events: List[Dict[str, Any]] = []
        self.active_scan: ActiveScanTask = ActiveScanTask()

    def set_watcher(self, path: Path, auto_quarantine: bool = False) -> None:
        with self.lock:
            if self.watcher:
                self.watcher.stop()
                self.watcher = None

            def event_callback(result: ScanResult, q_record: Optional[QuarantineRecord]) -> None:
                with self.lock:
                    self.recent_events.append({
                        "timestamp": time.time(),
                        "file_path": str(result.file_path),
                        "status": result.status.value,
                        "is_infected": result.is_infected,
                        "threat_name": result.threat.threat_name if result.threat else None,
                        "quarantined": q_record is not None,
                        "record_id": q_record.record_id if q_record else None,
                    })
                    if len(self.recent_events) > 100:
                        self.recent_events.pop(0)

            self.watcher = FileSystemWatcher(
                watch_paths=[path],
                recursive=True,
                auto_quarantine=auto_quarantine,
                on_event_callback=event_callback,
            )
            self.watched_path = path
            self.auto_quarantine_live = auto_quarantine
            self.watcher.start()

    def stop_watcher(self) -> None:
        with self.lock:
            if self.watcher:
                self.watcher.stop()
                self.watcher = None
            self.watched_path = None


state = APIState()


class PulseGuardRequestHandler(BaseHTTPRequestHandler):
    """HTTP request dispatcher for all local UI endpoints."""

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/status":
            self.handle_get_status()
        elif path == "/api/quarantine":
            self.handle_get_quarantine()
        elif path == "/api/processes":
            self.handle_get_processes(query)
        elif path == "/api/events":
            self.handle_get_events()
        elif path == "/api/scan/progress":
            self.handle_get_scan_progress()
        elif path == "/api/config":
            self.handle_get_config()
        elif path == "/api/vulnerabilities/scan":
            self.handle_get_vulnerabilities_scan()
        else:
            self._send_json_response({"error": f"Endpoint not found: {path}"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except json.JSONDecodeError as exc:
            self._send_json_response({"error": f"Invalid JSON payload: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/scan":
            self.handle_post_scan(body)
        elif path == "/api/scan/start":
            self.handle_post_scan_start(body)
        elif path == "/api/scan/stop":
            self.handle_post_scan_stop()
        elif path == "/api/watch/toggle":
            self.handle_post_watch_toggle(body)
        elif path == "/api/quarantine/restore":
            self.handle_post_quarantine_restore(body)
        elif path == "/api/quarantine/delete":
            self.handle_post_quarantine_delete(body)
        elif path == "/api/ai/scan":
            self.handle_post_ai_scan(body)
        elif path == "/api/ai/test":
            self.handle_post_ai_test(body)
        elif path == "/api/config":
            self.handle_post_config(body)
        elif path == "/api/vulnerabilities/remediate":
            self.handle_post_vulnerabilities_remediate(body)
        else:
            self._send_json_response({"error": f"Endpoint not found: {path}"}, status=HTTPStatus.NOT_FOUND)

    def handle_get_status(self) -> None:
        sig_count = _default_engine.signature_db.total_hash_signatures + _default_engine.signature_db.total_byte_patterns
        quarantine_items = list_quarantine()
        with state.lock:
            watcher_active = state.watcher is not None and state.watcher.is_running
            watched_path = str(state.watched_path) if state.watched_path else None

        self._send_json_response({
            "engine": "ONLINE",
            "signatures": sig_count,
            "watcher_active": watcher_active,
            "watched_path": watched_path,
            "quarantine_count": len(quarantine_items),
            "vault_path": str(QuarantineManager().vault_dir),
            "ai_configured": _default_ai_scanner.is_configured(),
            "ai_model": _default_ai_scanner.model,
        })

    def handle_post_scan(self, body: Dict[str, Any]) -> None:
        target_path_str = body.get("path")
        if not target_path_str:
            self._send_json_response({"error": "Missing required field: 'path'"}, status=HTTPStatus.BAD_REQUEST)
            return

        target_path = Path(target_path_str)
        if not target_path.exists():
            self._send_json_response({"error": f"Path does not exist: {target_path_str}"}, status=HTTPStatus.NOT_FOUND)
            return

        recursive = bool(body.get("recursive", True))
        auto_quarantine = bool(body.get("quarantine", False))

        if target_path.is_file():
            results = [_default_engine.scan_file(target_path)]
        else:
            results = _default_engine.scan_directory(target_path, recursive=recursive)

        response_results: List[Dict[str, Any]] = []
        infected_count = 0

        for r in results:
            is_inf = r.is_infected
            threat_name = r.threat.threat_name if r.threat else None
            q_id = None

            if is_inf:
                infected_count += 1
                if auto_quarantine and r.threat and r.file_path.exists():
                    try:
                        q_rec = quarantine_file(r.file_path, r.threat)
                        q_id = q_rec.record_id
                    except QuarantineError as q_err:
                        logger.error("Auto-quarantine failed for %s: %s", r.file_path, q_err)

            response_results.append({
                "file_path": str(r.file_path),
                "status": r.status.value,
                "is_infected": is_inf,
                "file_hash": r.file_hash,
                "threat_name": threat_name,
                "severity": r.threat.severity.value if r.threat else None,
                "scan_duration_ms": r.scan_duration_ms,
                "quarantine_id": q_id,
            })

        self._send_json_response({
            "results": response_results,
            "scanned_count": len(results),
            "infected_count": infected_count,
        })

    def handle_post_scan_start(self, body: Dict[str, Any]) -> None:
        scan_type = body.get("scan_type", "custom")
        raw_path = body.get("path")
        recursive = bool(body.get("recursive", True))
        auto_q = bool(body.get("quarantine", False))  # Default safe: report first

        target_paths: List[Path] = []
        if scan_type == "quick":
            user_home = Path.home()
            quick_cands = [
                user_home / "Downloads",
                user_home / "Desktop",
                Path(os.environ.get("TEMP", str(user_home / "AppData" / "Local" / "Temp"))),
                user_home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            ]
            for cand in quick_cands:
                if cand.exists():
                    target_paths.append(cand)
        elif scan_type == "system":
            user_home = Path.home()
            target_paths.append(user_home)
        else:
            if not raw_path:
                self._send_json_response({"error": "Missing 'path' parameter for custom scan"}, status=HTTPStatus.BAD_REQUEST)
                return
            target_paths.append(Path(raw_path))

        state.active_scan.start_scan(target_paths, scan_type=scan_type, recursive=recursive, auto_quarantine=auto_q)
        self._send_json_response({"started": True, "scan_type": scan_type, "targets": [str(p) for p in target_paths]})

    def handle_get_scan_progress(self) -> None:
        self._send_json_response(state.active_scan.get_progress())

    def handle_post_scan_stop(self) -> None:
        state.active_scan.stop_scan()
        self._send_json_response({"stopped": True})

    def handle_post_watch_toggle(self, body: Dict[str, Any]) -> None:
        activate = bool(body.get("active", False))
        watch_path_str = body.get("path")
        auto_q = bool(body.get("quarantine", True))

        if activate:
            if not watch_path_str:
                self._send_json_response({"error": "Missing 'path' to activate watcher"}, status=HTTPStatus.BAD_REQUEST)
                return
            watch_path = Path(watch_path_str)
            if not watch_path.exists():
                self._send_json_response({"error": f"Path not found: {watch_path_str}"}, status=HTTPStatus.NOT_FOUND)
                return
            state.set_watcher(watch_path, auto_quarantine=auto_q)
            self._send_json_response({"watcher_active": True, "watched_path": str(watch_path)})
        else:
            state.stop_watcher()
            self._send_json_response({"watcher_active": False, "watched_path": None})

    def handle_get_quarantine(self) -> None:
        records = list_quarantine()
        out: List[Dict[str, Any]] = []
        for r in records:
            out.append({
                "record_id": r.record_id,
                "original_path": str(r.original_path),
                "threat_name": r.threat.threat_name if r.threat else "Unknown Threat",
                "threat_type": r.threat.threat_type if r.threat else "generic",
                "severity": r.threat.severity.value if r.threat else "HIGH",
                "quarantined_at": r.quarantined_at.isoformat(),
                "file_hash": r.file_hash,
                "is_restored": r.is_restored,
            })
        self._send_json_response({"records": out})

    def handle_post_quarantine_restore(self, body: Dict[str, Any]) -> None:
        record_id = body.get("record_id")
        dest_str = body.get("dest")
        if not record_id:
            self._send_json_response({"error": "Missing 'record_id'"}, status=HTTPStatus.BAD_REQUEST)
            return

        dest = Path(dest_str) if dest_str else None
        try:
            restored = restore_file(record_id, destination=dest)
            self._send_json_response({"success": True, "restored_path": str(restored)})
        except QuarantineError as q_err:
            self._send_json_response({"success": False, "error": str(q_err)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_post_quarantine_delete(self, body: Dict[str, Any]) -> None:
        record_id = body.get("record_id")
        if not record_id:
            self._send_json_response({"error": "Missing 'record_id'"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            delete_quarantine(record_id)
            self._send_json_response({"success": True})
        except QuarantineError as q_err:
            self._send_json_response({"success": False, "error": str(q_err)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_get_processes(self, query: Dict[str, List[str]]) -> None:
        limit = int(query.get("limit", [50])[0])
        procs: List[Dict[str, Any]] = []
        infected_count = 0

        for p_res in scan_running_processes():
            if len(procs) >= limit:
                break
            is_inf = p_res.scan_result.is_infected if p_res.scan_result else False
            if is_inf:
                infected_count += 1
            procs.append({
                "pid": p_res.pid,
                "name": p_res.name,
                "exe_path": str(p_res.exe_path) if p_res.exe_path else None,
                "is_infected": is_inf,
                "threat_name": (
                    p_res.scan_result.threat.threat_name
                    if p_res.scan_result and p_res.scan_result.threat
                    else None
                ),
            })

        self._send_json_response({
            "processes": procs,
            "scanned_count": len(procs),
            "infected_count": infected_count,
        })

    def handle_get_events(self) -> None:
        with state.lock:
            events = list(state.recent_events)
        self._send_json_response({"events": events})

    def handle_get_config(self) -> None:
        key = _default_ai_scanner.api_key or ""
        masked = f"{key[:6]}...{key[-4:]}" if len(key) >= 12 else ("Configurée" if key else "")
        self._send_json_response({
            "nvidia_api_key_configured": bool(key),
            "nvidia_api_key_masked": masked,
            "nvidia_model": _default_ai_scanner.model,
        })

    def handle_post_config(self, body: Dict[str, Any]) -> None:
        new_key = body.get("nvidia_api_key")
        new_model = body.get("nvidia_model")
        if new_key is not None:
            _default_ai_scanner.set_api_key(str(new_key))
        if new_model:
            _default_ai_scanner.set_model(str(new_model))
        self._send_json_response({
            "success": True,
            "nvidia_api_key_configured": _default_ai_scanner.is_configured(),
            "nvidia_model": _default_ai_scanner.model,
        })

    def handle_post_ai_scan(self, body: Dict[str, Any]) -> None:
        target_path_str = body.get("path")
        if not target_path_str:
            self._send_json_response({"error": "Missing required field: 'path'"}, status=HTTPStatus.BAD_REQUEST)
            return

        target_path = Path(target_path_str)
        if not target_path.exists():
            self._send_json_response({"error": f"Fichier introuvable: {target_path_str}"}, status=HTTPStatus.NOT_FOUND)
            return

        analysis = _default_ai_scanner.analyze_file(target_path)
        self._send_json_response(analysis)

    def handle_post_ai_test(self, body: Dict[str, Any]) -> None:
        api_key = body.get("api_key")
        res = _default_ai_scanner.test_connection(api_key=api_key)
        self._send_json_response(res)

    def handle_get_vulnerabilities_scan(self) -> None:
        findings = _default_vuln_scanner.scan_all()
        score = _default_vuln_scanner.calculate_security_score()
        out = []
        for f in findings:
            out.append({
                "vuln_id": f.vuln_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "affected_item": f.affected_item,
                "cve_cwe": f.cve_cwe,
                "remediation": f.remediation,
                "can_auto_fix": f.can_auto_fix,
                "is_fixed": f.is_fixed,
            })
        self._send_json_response({
            "security_score": score,
            "total_flaws": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == ThreatSeverity.CRITICAL),
            "high_count": sum(1 for f in findings if f.severity == ThreatSeverity.HIGH),
            "medium_count": sum(1 for f in findings if f.severity == ThreatSeverity.MEDIUM),
            "findings": out,
        })

    def handle_post_vulnerabilities_remediate(self, body: Dict[str, Any]) -> None:
        vuln_id = body.get("vuln_id")
        if not vuln_id:
            self._send_json_response({"error": "Missing 'vuln_id'"}, status=HTTPStatus.BAD_REQUEST)
            return

        success, msg = _default_vuln_scanner.remediate_vulnerability(vuln_id)
        self._send_json_response({"success": success, "message": msg, "vuln_id": vuln_id})


class PulseGuardAPIServer:
    """Server lifecycle manager running in a background thread."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, block: bool = False) -> None:
        self.server = ThreadingHTTPServer((self.host, self.port), PulseGuardRequestHandler)
        logger.info("PulseGuard API Server running on http://%s:%d", self.host, self.port)
        if block:
            self.server.serve_forever()
        else:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        state.active_scan.stop_scan()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        state.stop_watcher()
        logger.info("PulseGuard API Server stopped.")


def start_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, block: bool = True) -> PulseGuardAPIServer:
    """Convenience function to start the REST API server."""
    server = PulseGuardAPIServer(host=host, port=port)
    server.start(block=block)
    return server
