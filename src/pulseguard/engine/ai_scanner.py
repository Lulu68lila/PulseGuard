"""PulseGuard NVIDIA Nemotron AI Threat Scanner.

Integrates NVIDIA's Nemotron 3 Ultra 550B (and LLaMA 3.1 Nemotron 70B)
via the NVIDIA NIM API (https://build.nvidia.com/nvidia/nemotron-3-ultra-550b-a55b)
to conduct advanced AI-driven malware, ransomware, and zero-day threat analysis.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

logger = logging.getLogger("pulseguard.ai_scanner")

DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
FALLBACK_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
CONFIG_PATH = Path.home() / ".pulseguard" / "config.json"


def get_stored_config() -> Dict[str, Any]:
    """Load PulseGuard persistent configuration."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug("Failed reading config: %s", e)
    return {}


def save_stored_config(cfg: Dict[str, Any]) -> None:
    """Save PulseGuard persistent configuration."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        logger.error("Failed saving config: %s", e)


class NemotronAIScanner:
    """AI Malware and Ransomware Analyst powered by NVIDIA Nemotron."""

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL) -> None:
        self.config = get_stored_config()
        self.api_key = (
            api_key
            or os.environ.get("NVIDIA_API_KEY")
            or self.config.get("nvidia_api_key", "")
        )
        self.model = model or self.config.get("nvidia_model", DEFAULT_MODEL)

    def set_api_key(self, api_key: str) -> None:
        """Update and persist the NVIDIA API key."""
        self.api_key = api_key.strip()
        self.config["nvidia_api_key"] = self.api_key
        save_stored_config(self.config)

    def set_model(self, model: str) -> None:
        """Update and persist the target AI model."""
        self.model = model.strip()
        self.config["nvidia_model"] = self.model
        save_stored_config(self.config)

    def is_configured(self) -> bool:
        """Check if an API key is available."""
        return bool(self.api_key and len(self.api_key) > 5)

    def test_connection(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Test API connectivity to the NVIDIA Nemotron endpoint."""
        key = api_key or self.api_key
        if not key:
            return {
                "success": False,
                "error": "Aucune clé API NVIDIA fournie. Veuillez renseigner votre clé nvapi-... dans les Paramètres.",
            }

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "PulseGuard-Antivirus/0.2.0",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a test probe."},
                {"role": "user", "content": "Respond with single word: READY"},
            ],
            "max_tokens": 16,
            "temperature": 0.1,
        }

        try:
            req = urllib.request.Request(
                NVIDIA_API_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choice = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                return {
                    "success": True,
                    "model": self.model,
                    "response": choice,
                    "message": f"Connexion réussie au modèle NVIDIA {self.model} !",
                }
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="ignore")
            # If model name failed, attempt fallback to llama-3.1-nemotron-70b-instruct
            if exc.code == 404 or "model" in err_body.lower():
                return self._test_fallback_model(key)
            return {
                "success": False,
                "status_code": exc.code,
                "error": f"Erreur API NVIDIA ({exc.code}): {err_body}",
            }
        except Exception as exc:
            return {"success": False, "error": f"Erreur de connexion : {str(exc)}"}

    def _test_fallback_model(self, key: str) -> Dict[str, Any]:
        """Fallback probe using 70B model."""
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": FALLBACK_MODEL,
            "messages": [{"role": "user", "content": "READY"}],
            "max_tokens": 10,
        }
        try:
            req = urllib.request.Request(
                NVIDIA_API_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                self.model = FALLBACK_MODEL
                self.config["nvidia_model"] = FALLBACK_MODEL
                save_stored_config(self.config)
                return {
                    "success": True,
                    "model": FALLBACK_MODEL,
                    "message": f"Connecté avec succès au modèle de secours NVIDIA {FALLBACK_MODEL} !",
                }
        except Exception as exc:
            return {"success": False, "error": f"Erreur modèle : {str(exc)}"}

    def extract_telemetry(self, file_path: Path, max_bytes: int = 16384) -> Dict[str, Any]:
        """Extract rich static telemetry from a target file for LLM reasoning."""
        if not file_path.exists() or not file_path.is_file():
            return {"error": "Fichier introuvable"}

        stat = file_path.stat()
        file_size = stat.st_size

        try:
            with open(file_path, "rb") as f:
                header_bytes = f.read(min(max_bytes, file_size))
        except Exception as err:
            return {"error": f"Impossible de lire le fichier: {err}"}

        # Shannon entropy
        from pulseguard.engine.heuristics import calculate_entropy
        entropy = round(calculate_entropy(header_bytes), 3)

        # ASCII strings extraction
        strings = re.findall(b"[ -~]{5,}", header_bytes)
        decoded_strings = [s.decode("latin-1", errors="ignore") for s in strings[:60]]

        # Text snippet if applicable
        is_text = False
        text_snippet = ""
        ext = file_path.suffix.lower()
        if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".txt", ".json", ".xml"}:
            is_text = True
            text_snippet = header_bytes[:4096].decode("utf-8", errors="ignore")

        # Suspicious API keywords matching
        suspicious_keywords = [
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
            "vssadmin", "delete shadows", "wbadmin", "bcdedit",
            "powershell -enc", "DownloadString", "HttpOpenRequest",
            "RegSetValueEx", "IsDebuggerPresent", "CryptEncrypt",
        ]
        detected_keywords = [
            kw for kw in suspicious_keywords
            if kw.lower().encode("utf-8") in header_bytes.lower()
        ]

        return {
            "file_name": file_path.name,
            "extension": ext,
            "file_size": file_size,
            "entropy": entropy,
            "is_pe": header_bytes[:2] == b"MZ",
            "detected_keywords": detected_keywords,
            "extracted_strings": decoded_strings[:30],
            "is_text_script": is_text,
            "text_snippet": text_snippet,
        }

    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Perform deep threat reasoning using NVIDIA Nemotron on a file."""
        telemetry = self.extract_telemetry(file_path)
        if "error" in telemetry:
            return {"success": False, "error": telemetry["error"]}

        if not self.is_configured():
            # Graceful local fallback simulation when API key not yet set
            return self._local_heuristic_report(file_path, telemetry)

        # Build prompt for NVIDIA Nemotron
        system_prompt = (
            "You are PulseGuard AI Nemotron Threat Sentinel, an elite cybersecurity and reverse-engineering "
            "foundation model developed by NVIDIA and PulseGuard. "
            "Analyze the given file telemetry, extracted strings, keywords, entropy, and code snippets. "
            "Determine if the file represents a Ransomware, Malware, Suspicious Dropper, or Clean file.\n\n"
            "You MUST respond ONLY with a valid, well-formed JSON object formatted exactly as:\n"
            "{\n"
            '  "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "RANSOMWARE",\n'
            '  "confidence_score": integer between 0 and 100,\n'
            '  "threat_name": "Short descriptive threat designation (e.g. Ransom.Nemotron.ShadowKill or Clean.SafeUtility)",\n'
            '  "threat_type": "ransomware" | "trojan" | "dropper" | "spyware" | "clean",\n'
            '  "ransomware_indicators": ["list of specific ransomware behaviors observed or suspected"],\n'
            '  "mitre_attack_tactics": ["list of MITRE ATT&CK techniques, e.g. T1486 Data Encrypted for Impact"],\n'
            '  "analysis": "2-3 paragraphs in French describing the inner mechanism, why it was flagged, and threat analysis.",\n'
            '  "remediation_steps": ["step 1 in French", "step 2 in French"]\n'
            "}"
        )

        user_prompt = (
            f"Please analyze this file artifact:\n"
            f"- File Name: {telemetry['file_name']}\n"
            f"- File Extension: {telemetry['extension']}\n"
            f"- Size: {telemetry['file_size']} bytes\n"
            f"- Shannon Entropy: {telemetry['entropy']}/8.0\n"
            f"- Windows PE Binary (MZ header): {telemetry['is_pe']}\n"
            f"- Suspicious Keywords: {', '.join(telemetry['detected_keywords']) or 'None'}\n"
            f"- Extracted Strings sample: {json.dumps(telemetry['extracted_strings'][:20])}\n"
        )
        if telemetry.get("is_text_script") and telemetry.get("text_snippet"):
            user_prompt += f"\nCode Content Snippet:\n```\n{telemetry['text_snippet'][:2000]}\n```"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "PulseGuard-Nemotron-Engine/0.2.0",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
        }

        try:
            req = urllib.request.Request(
                NVIDIA_API_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_text = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

                # Parse JSON block
                json_match = re.search(r"\{[\s\S]*\}", raw_text)
                if json_match:
                    ai_result = json.loads(json_match.group(0))
                else:
                    ai_result = {
                        "verdict": "SUSPICIOUS",
                        "confidence_score": 65,
                        "threat_name": "AI.Nemotron.UnstructuredVerdict",
                        "threat_type": "suspicious",
                        "ransomware_indicators": [],
                        "mitre_attack_tactics": [],
                        "analysis": raw_text,
                        "remediation_steps": ["Inspecter manuellement le fichier"],
                    }

                ai_result["success"] = True
                ai_result["model_used"] = self.model
                ai_result["telemetry"] = telemetry
                return ai_result

        except urllib.error.HTTPError as exc:
            err_msg = exc.read().decode("utf-8", errors="ignore")
            logger.error("NVIDIA API call failed: %s - %s", exc.code, err_msg)
            fallback = self._local_heuristic_report(file_path, telemetry)
            fallback["warning"] = f"Échec de l'appel API NVIDIA ({exc.code}). Résultat heuristique local affiché."
            return fallback
        except Exception as exc:
            logger.error("NVIDIA analysis error: %s", exc)
            fallback = self._local_heuristic_report(file_path, telemetry)
            fallback["warning"] = f"Erreur réseau: {exc}. Analyse locale affichée."
            return fallback

    def _local_heuristic_report(self, file_path: Path, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured analysis when API key is not configured."""
        has_keywords = bool(telemetry.get("detected_keywords"))
        high_entropy = telemetry.get("entropy", 0.0) >= 7.3

        if "vssadmin" in telemetry.get("detected_keywords", []) or "wbadmin" in telemetry.get("detected_keywords", []):
            verdict = "RANSOMWARE"
            score = 92
            threat_name = "Ransom.Heuristic.ShadowWiper"
            tactics = ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery"]
            remed = ["Isoler immédiatement le fichier", "Restaurer les clichés instantanés VSS"]
        elif has_keywords or (high_entropy and telemetry.get("is_pe")):
            verdict = "SUSPICIOUS"
            score = 75
            threat_name = "Heuristic.Suspicious.HighEntropyPayload"
            tactics = ["T1027 Obfuscated/Compressed Code"]
            remed = ["Mettre en quarantaine sous clé AES-256", "Vérifier la provenance de l'exécutable"]
        else:
            verdict = "CLEAN"
            score = 15
            threat_name = "Clean.VerifiedStructure"
            tactics = []
            remed = ["Aucune action requise"]

        analysis = (
            f"Analyse structurelle préliminaire effectuée pour **{telemetry['file_name']}**. "
            f"Entropie de Shannon mesurée à {telemetry['entropy']}/8.0. "
            f"{'Mots-clés suspects interceptés : ' + ', '.join(telemetry['detected_keywords']) if has_keywords else 'Aucun motif de commande malveillante intercepté.'}\n\n"
            "> [!NOTE] Pour activer l'analyse cognitive complète avec **NVIDIA Nemotron 3 Ultra 550B**, "
            "veuillez configurer votre clé API NVIDIA dans l'onglet **Paramètres** de PulseGuard."
        )

        return {
            "success": True,
            "verdict": verdict,
            "confidence_score": score,
            "threat_name": threat_name,
            "threat_type": verdict.lower(),
            "ransomware_indicators": [kw for kw in telemetry.get("detected_keywords", []) if "vss" in kw or "crypt" in kw],
            "mitre_attack_tactics": tactics,
            "analysis": analysis,
            "remediation_steps": remed,
            "model_used": "Heuristique Locale (Clé API NVIDIA non configurée)",
            "telemetry": telemetry,
        }
