"""Small HTTP client used by the deployed Streamlit console."""

from __future__ import annotations

from typing import Any

import httpx


class SentinelApiError(RuntimeError):
    pass


class SentinelApiClient:
    def __init__(self, base_url: str, token: str = "", timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = dict(kwargs.pop("headers", {}))
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = httpx.request(
                method, f"{self.base_url}{path}", headers=headers,
                timeout=self.timeout, **kwargs,
            )
        except httpx.HTTPError as exc:
            raise SentinelApiError(f"API connection failed: {exc}") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise SentinelApiError(f"API returned {response.status_code}: {detail}")
        if response.status_code == 204:
            return None
        return response.json()

    def login(self, username: str, password: str) -> str:
        result = self._request(
            "POST", "/auth/token", data={"username": username, "password": password}
        )
        return str(result["access_token"])

    def get(self, path: str, **params: Any) -> Any:
        clean_params = {key: value for key, value in params.items() if value is not None}
        return self._request("GET", path, params=clean_params or None)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._request("POST", path, json=body or {})

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("PATCH", path, json=body)
