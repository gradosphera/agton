from __future__ import annotations

import json
import threading
import time
from collections.abc import Mapping
from typing import Any, Literal, overload, Self

import requests
import requests.auth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


JSON = dict[str, Any] | list[Any] | str | int | float | bool | None

class ApiError(requests.HTTPError):
    """Raised for non-2xx responses with handy context attached."""

    def __init__(self, message: str, response: requests.Response):
        try:
            payload = response.json()
        except Exception:
            payload = response.text
        self.status_code: int = response.status_code
        self.response: requests.Response = response
        self.payload: Any = payload
        super().__init__(message, response=response)

    def __str__(self) -> str:  # pragma: no cover
        base = f"{self.status_code} {self.response.reason}"
        try:
            detail = json.dumps(self.payload, ensure_ascii=False)[:500]
        except Exception:
            detail = str(self.payload)[:500]
        return f"{base} - {detail}"


class BaseApiClient:
    """
    Minimal base for HTTP API clients using `requests`.
    Subclass and add typed methods that call self.get/post/... with paths like "/v1/things".
    """

    DEFAULT_TIMEOUT: float = 15.0  # seconds

    def __init__(
        self,
        base_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        bearer_token: str | None = None,
        api_key: tuple[str, str] | None = None,  # (header_name, value)
        auth: requests.auth.AuthBase | None = None,
        timeout: float | None = None,
        retries: int | None = 3,
        backoff_factor: float = 0.4,
        status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504),
        allowed_methods: tuple[str, ...] = ("HEAD", "GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"),
        proxies: Mapping[str, str] | None = None,
        verify: bool | str = True,  # path to CA bundle or bool
        user_agent: str = "BaseApiClient/2.0 (+https://example.com)",
        rps: float | None = None,
    ) -> None:
        if not base_url.endswith("/"):
            base_url += "/"
        self.base_url = base_url
        self.verify = verify
        self.proxies = dict(proxies) if proxies else None
        self.timeout = float(timeout) if timeout is not None else self.DEFAULT_TIMEOUT
        if rps is not None and rps <= 0:
            raise ValueError("rps should be positive")
        self.rps = float(rps) if rps is not None else None
        self._min_request_interval = (1.0 / self.rps) if self.rps is not None else 0.0
        self._request_gate = threading.Lock()
        self._next_request_at = 0.0

        sess = requests.Session()

        # Retries with exponential backoff, including on 429 rate limits.
        if retries and retries > 0:
            retry = Retry(
                total=retries,
                connect=retries,
                read=retries,
                redirect=retries,
                status=retries,
                backoff_factor=backoff_factor,
                status_forcelist=frozenset(status_forcelist),
                allowed_methods=frozenset(m.upper() for m in allowed_methods),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
            sess.mount("https://", adapter)
            sess.mount("http://", adapter)

        # Default headers
        self._default_headers: dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "application/json, */*;q=0.1",
        }
        if headers:
            self._default_headers.update(headers)

        # Auth
        self._auth = auth
        if bearer_token:
            self._default_headers["Authorization"] = f"Bearer {bearer_token}"
        if api_key:
            key_header, key_value = api_key
            self._default_headers[key_header] = key_value

        self.session = sess

    # ---- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None: # type: ignore
        self.close()

    # ---- verb helpers -----------------------------------------------------

    def get(self, path: str, **kwargs) -> Any: # type: ignore
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Any: # type: ignore
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> Any: # type: ignore
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs) -> Any: # type: ignore
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> Any: # type: ignore
        return self.request("DELETE", path, **kwargs)

    # ---- core request -----------------------------------------------------

    @overload
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = ...,
        headers: Mapping[str, str] | None = ...,
        json: JSON = ...,
        data: Mapping[str, Any] | bytes | None = ...,
        files: Mapping[str, Any] | None = ...,
        timeout: float | None = ...,
        auth: requests.auth.AuthBase | None = ...,
        stream: Literal[True] = ...,
        allow_redirects: bool = ...,
        absolute_url: str | None = ...,
    ) -> requests.Response: ...
    @overload
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = ...,
        headers: Mapping[str, str] | None = ...,
        json: JSON = ...,
        data: Mapping[str, Any] | bytes | None = ...,
        files: Mapping[str, Any] | None = ...,
        timeout: float | None = ...,
        auth: requests.auth.AuthBase | None = ...,
        stream: Literal[False] = ...,
        allow_redirects: bool = ...,
        absolute_url: str | None = ...,
    ) -> Any: ...
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json: JSON = None,
        data: Mapping[str, Any] | bytes | None = None,
        files: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        auth: requests.auth.AuthBase | None = None,
        stream: bool = False,
        allow_redirects: bool = True,
        absolute_url: str | None = None,
    ) -> Any:
        """
        Core request method. Usually pass a relative `path` like "/v1/items".
        If you already have a full URL, pass it via `absolute_url` (path is ignored).
        """
        url = self._build_url(path) if not absolute_url else absolute_url

        req_headers = self._merge_headers(headers)
        self._wait_for_rate_limit()

        resp = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            headers=req_headers,
            json=json,
            data=data,
            files=files,
            timeout=self._coerce_timeout(timeout),
            auth=auth if auth is not None else self._auth,
            stream=stream,
            allow_redirects=allow_redirects,
            verify=self.verify,
            proxies=self.proxies,
        )

        if stream:  # caller handles streaming/closing
            self._raise_for_status(resp)
            return resp

        return self._handle_response(resp)

    # ---- internals --------------------------------------------------------

    def _build_url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        # allow paths with/without leading slash
        return f"{self.base_url}{path.lstrip('/')}"

    def _merge_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        merged = dict(self._default_headers)
        if headers:
            merged.update(headers)
        return merged

    def _coerce_timeout(self, timeout: float | None) -> float:
        return float(timeout) if timeout is not None else self.timeout

    def _wait_for_rate_limit(self) -> None:
        if self.rps is None:
            return
        with self._request_gate:
            now = time.monotonic()
            if now < self._next_request_at:
                time.sleep(self._next_request_at - now)
                now = time.monotonic()
            self._next_request_at = now + self._min_request_interval

    def _handle_response(self, resp: requests.Response) -> Any:
        self._raise_for_status(resp)

        ctype = resp.headers.get("Content-Type", "")
        if "json" in ctype:
            try:
                return resp.json()
            except json.JSONDecodeError:
                pass  # fall through to text

        if "text/" in ctype or not ctype:
            return resp.text
        return resp.content

    def _raise_for_status(self, resp: requests.Response) -> None:
        if 200 <= resp.status_code < 300:
            return
        method = resp.request.method if resp.request else "REQUEST"
        url = resp.url
        msg = f"{method} {url} -> {resp.status_code}"
        raise ApiError(msg, resp)
