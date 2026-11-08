"""
SENTRIX v5.0 — Local LLM Provider Interface
Integrates with locally running LLMs (such as Ollama) over a REST API.
Enforces zero telemetry, offline-first reliability, and clean fallback.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from core.config import get_config
from core.logger import log

class LocalLLMProvider:
    """Manages local LLM queries with health-checking, auto-model selection, and graceful timeouts."""

    def __init__(self):
        self.default_url = "http://localhost:11434"
        self.default_model = "llama3"
        self.timeout = 8.0  # short fail-fast timeout so UI stays snappy

    @property
    def base_url(self) -> str:
        return get_config("ollama_url", self.default_url).rstrip("/")

    @property
    def configured_model(self) -> str:
        return get_config("ollama_model", self.default_model)

    def is_available(self) -> bool:
        """Pings local Ollama service to check if it is active."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "SENTRIX-v5"})
            with urllib.request.urlopen(req, timeout=2.0) as res:
                return res.status == 200
        except Exception:
            return False

    def list_installed_models(self) -> List[str]:
        """Returns installed model names from Ollama."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "SENTRIX-v5"})
            with urllib.request.urlopen(req, timeout=3.0) as res:
                if res.status == 200:
                    data = json.loads(res.read().decode("utf-8"))
                    return [m.get("name") for m in data.get("models", []) if "name" in m]
        except Exception as e:
            log.debug(f"LocalLLMProvider: Model listesi alınamadı: {e}")
        return []

    def query(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Sends inference request to local Ollama. Returns structured dict or None if offline."""
        if not self.is_available():
            return None

        available_models = self.list_installed_models()
        model_to_use = self.configured_model
        if available_models and model_to_use not in available_models:
            model_to_use = available_models[0]

        payload = {
            "model": model_to_use,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=data_bytes,
                headers={"Content-Type": "application/json", "User-Agent": "SENTRIX-v5"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    res_body = json.loads(resp.read().decode("utf-8"))
                    return {
                        "text": res_body.get("response", "").strip(),
                        "model": model_to_use,
                        "source": f"Yerel LLM ({model_to_use})",
                        "total_duration": res_body.get("total_duration")
                    }
        except urllib.error.URLError as e:
            log.debug(f"LocalLLMProvider: Yerel LLM bağlantı hatası: {e.reason}")
        except Exception as e:
            log.debug(f"LocalLLMProvider: Çıkarım sırasında hata: {e}")

        return None

local_llm_provider = LocalLLMProvider()
