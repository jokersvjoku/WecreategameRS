import logging
from typing import Optional
import httpx
from app.config import get_settings

logger = logging.getLogger("patchpilot")


class GemmaClient:
    """HTTP client for Gemma 4 inference via DigitalOcean Gradient (OpenAI-compatible API)."""

    def __init__(self):
        self._settings = get_settings()

    @property
    def is_available(self) -> bool:
        return self._settings.ai_available

    async def generate(self, prompt: str, max_tokens: int = 2048) -> Optional[str]:
        """
        Send a prompt to Gemma 4 and return the response text.
        Returns None if AI is unavailable or the request fails.
        """
        if not self.is_available:
            logger.info("Gemma 4 not configured — skipping AI inference")
            return None

        endpoint = self._settings.gemma_api_url.rstrip("/") + "/chat/completions"

        headers = {
            "Authorization": f"Bearer {self._settings.gemma_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._settings.gemma_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior cybersecurity engineer. "
                        "Your job is to analyze code vulnerabilities and provide clear, "
                        "accurate security patches. Always provide working Python code. "
                        "Be concise and technical."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as exc:
            logger.error(f"Gemma API HTTP error: {exc.response.status_code} — {exc.response.text}")
            return None
        except httpx.RequestError as exc:
            logger.error(f"Gemma API request error: {exc}")
            return None
        except (KeyError, IndexError) as exc:
            logger.error(f"Gemma API unexpected response format: {exc}")
            return None
