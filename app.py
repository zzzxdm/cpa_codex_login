#!/usr/bin/env python3
"""Automate Codex OAuth login for a remote or local CLIProxyAPI instance."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dashboard import AUTH_FAILURE, PAGE_SIZES, QuotaCache, RuntimeState, account_summary, credential_status, matching_credentials, selected_credential
from admin_auth import AdminAuth, SESSION_COOKIE, SESSION_SECONDS

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"


def totp(secret: str, timestamp: int | None = None) -> str:
    """Generate a six-digit RFC 6238 code from a Base32 secret."""
    raw = base64.b32decode("".join(secret.split()).upper() + "=" * (-len(secret) % 8))
    counter = int((timestamp if timestamp is not None else time.time()) // 30).to_bytes(8, "big")
    digest = hmac.new(raw, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


class TwoFactorProvider:
    """Generate TOTP locally or call a configurable external 2FA endpoint."""
    def __init__(self, config: TwoFactorConfig | None = None):
        self.config = config or TwoFactorConfig("local", "", "", "GET", "code", {}, {}, 10)

    @staticmethod
    def _render(value, secret, encode=False):
        if isinstance(value, str):
            replacement = urllib.parse.quote(secret, safe="") if encode else secret
            for marker in ("{secret}", "{SECRET}", "{SECRET_KEY}"):
                value = value.replace(marker, replacement)
            return value
        if isinstance(value, dict):
            return {key: TwoFactorProvider._render(item, secret, encode) for key, item in value.items()}
        if isinstance(value, list):
            return [TwoFactorProvider._render(item, secret, encode) for item in value]
        return value

    @staticmethod
    def _field(payload, field):
        current = payload
        for part in field.split('.'):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def code(self, secret):
        if self.config.mode == "local":
            return totp(secret)
        secret = "".join(secret.split()).upper()
        url = self._render(self.config.api_url, secret, encode=True)
        body = self._render(self.config.request_body, secret)
        data = json.dumps(body).encode() if self.config.method == "POST" else None
        headers = {"Accept": "application/json", **self._render(self.config.headers, secret)}
        if data is not None:
            headers.setdefault("Content-Type", "application/json")
        try:
            request = urllib.request.Request(url, data=data, headers=headers, method=self.config.method)
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(65537).decode(errors="replace")
                if len(raw) > 65536:
                    raise ValueError("response too large")
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("2FA 接口请求失败，请检查 two_factor 配置和网络连接") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            # URL templates may contain the TOTP secret; never expose request details.
            raise RuntimeError("2FA 接口请求失败，请检查 two_factor 配置和网络连接") from None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError("2FA 接口返回格式不是 JSON") from None
        if isinstance(payload, dict) and payload.get("valid") is False:
            raise RuntimeError("2FA 服务返回密钥无效")
        value = self._field(payload, self.config.code_field)
        if type(value) is int and 0 <= value <= 999999:
            value = f"{value:06d}"
        if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) != 6:
            raise RuntimeError(f"2FA 接口未返回 6 位验证码（字段：{self.config.code_field}）")
        return value


@dataclass(frozen=True)
class Account:
    email: str
    password: str
    totp_secret: str


@dataclass(frozen=True)
class TwoFactorConfig:
    mode: str
    page_url: str
    api_url: str
    method: str
    code_field: str
    request_body: dict[str, Any]
    headers: dict[str, str]
    timeout: int


@dataclass(frozen=True)
class Config:
    cpa_url: str
    management_key: str
    listen_host: str
    listen_port: int
    browser_mode: str
    browser_headless: bool
    browser_channel: str
    auth_concurrency: int
    auto_reauth: bool
    auto_reauth_interval: int
    open_browser: bool
    accounts_file: Path
    accounts: tuple[Account, ...]
    admin_password: str
    two_factor: TwoFactorConfig


def parse_accounts_file(path: Path) -> list[Account]:
    if not path.exists():
        return []
    accounts: list[Account] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("----", 2)]
        if len(parts) != 3 or not all(parts):
            raise ValueError(f"{path}:{line_number} must use email--password--totp format")
        accounts.append(Account(*parts))
    return accounts


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def load_config(path: Path) -> Config:
    data = json.loads(path.read_text(encoding="utf-8"))
    cpa = data.get("cpa", {})
    server = data.get("server", {})
    browser = data.get("browser", {})
    two_factor_data = data.get("two_factor", {})
    if not isinstance(two_factor_data, dict):
        raise ValueError("two_factor must be an object")
    accounts_name = str(data.get("accounts_file", "accounts.txt")).strip()
    if not accounts_name:
        raise ValueError("accounts_file is required")
    accounts_file = (path.parent / accounts_name).resolve()
    accounts = tuple(parse_accounts_file(accounts_file))
    management_key = str(os.getenv("CPA_MANAGEMENT_KEY", cpa.get("management_key", ""))).strip()
    if not management_key:
        raise ValueError("CPA_MANAGEMENT_KEY or config.cpa.management_key is required")
    browser_mode = str(browser.get("mode", "headless")).strip().lower()
    if browser_mode not in {"headless", "local"}:
        raise ValueError("browser.mode must be headless or local")
    browser_headless = browser_mode == "headless"
    auth_concurrency = data.get("auth_concurrency", 4)
    if type(auth_concurrency) is not int or not 1 <= auth_concurrency <= 32:
        raise ValueError("auth_concurrency must be an integer between 1 and 32")
    auto_interval = data.get("auto_reauth_interval", 60)
    if type(auto_interval) is not int or not 10 <= auto_interval <= 3600:
        raise ValueError("auto_reauth_interval must be an integer between 10 and 3600")
    if type(data.get("auto_reauth", False)) is not bool:
        raise ValueError("auto_reauth must be a boolean")
    two_factor_mode = str(two_factor_data.get("mode", "local")).strip().lower()
    if two_factor_mode not in {"local", "api"}:
        raise ValueError("two_factor.mode must be local or api")
    two_factor_method = str(two_factor_data.get("method", "GET")).strip().upper()
    if two_factor_method not in {"GET", "POST"}:
        raise ValueError("two_factor.method must be GET or POST")
    two_factor_url = str(two_factor_data.get("api_url", "")).strip()
    if two_factor_mode == "api" and not two_factor_url:
        raise ValueError("two_factor.api_url is required when mode is api")
    if two_factor_mode == "api":
        parsed_two_factor = urllib.parse.urlsplit(two_factor_url)
        if parsed_two_factor.scheme not in {"http", "https"} or not parsed_two_factor.hostname:
            raise ValueError("two_factor.api_url must be an HTTP or HTTPS URL")
    body = two_factor_data.get("request_body", {})
    if not isinstance(body, dict):
        raise ValueError("two_factor.request_body must be an object")
    headers = two_factor_data.get("headers", {})
    if not isinstance(headers, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
        raise ValueError("two_factor.headers must be a string object")
    timeout = two_factor_data.get("timeout", 10)
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise ValueError("two_factor.timeout must be an integer between 1 and 60")
    return Config(
        cpa_url=str(os.getenv("CPA_URL", cpa.get("url", "http://localhost:8317"))).rstrip("/"),
        management_key=management_key,
        listen_host=str(server.get("host", "127.0.0.1")),
        listen_port=int(server.get("port", 8765)),
        browser_mode=browser_mode,
        browser_headless=browser_headless,
        browser_channel=str(browser.get("channel", "chromium" if browser_headless else "chrome")),
        auth_concurrency=auth_concurrency,
        auto_reauth=data.get("auto_reauth", False),
        auto_reauth_interval=auto_interval,
        open_browser=bool(browser.get("open_browser", True)),
        accounts_file=accounts_file,
        accounts=accounts,
        admin_password=os.getenv("ADMIN_PASSWORD") or server.get("admin_password", ""),
        two_factor=TwoFactorConfig(two_factor_mode, str(two_factor_data.get("page_url", "https://2fa.kim/")).strip(), two_factor_url,
                                   two_factor_method, str(two_factor_data.get("code_field", "code")).strip() or "code",
                                   body, headers, timeout),
    )


def is_private_cpa_url(raw_url: str) -> bool:
    host = (urllib.parse.urlsplit(raw_url).hostname or "").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain", "host.docker.internal"} or host.endswith(".localhost"):
        return True

    def private_address(address: str) -> bool:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return (ip.is_private or ip.is_loopback or ip.is_link_local) and not (ip.is_unspecified or ip.is_multicast)

    try:
        return private_address(host)
    except ValueError:
        try:
            addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False
        return bool(addresses) and all(private_address(item[4][0]) for item in addresses)


class CPAAPIError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.upstream_auth_failure = False


class CPAClient:
    def __init__(self, base_url: str, key: str, browser_mode: str = "headless", browser_channel: str = "chromium"):
        self.base = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        self.browser_mode = browser_mode
        self.browser_channel = browser_channel
        self.browser_transport = not is_private_cpa_url(self.base)
        self._browser_tasks = queue.Queue()
        self._browser_lock = threading.Lock()
        self._browser_thread = None
        self._closed = False

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.browser_transport:
            return self._browser_request(method, path, body)
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = response.read().decode()
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise self._http_error(exc.code, detail) from exc
        except urllib.error.URLError as exc:
            host = urllib.parse.urlparse(self.base).netloc or self.base
            raise CPAAPIError(0, f"无法连接 CPA（目标地址：{host}）：{exc.reason}") from exc

    def _browser_request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        future = Future()
        with self._browser_lock:
            if self._closed:
                raise CPAAPIError(0, "CPA 客户端已关闭")
            if self._browser_thread is None:
                self._browser_thread = threading.Thread(target=self._browser_worker, daemon=True, name="cpa-browser")
                self._browser_thread.start()
            self._browser_tasks.put((method, path, body, future))
        return future.result()

    def _browser_worker(self) -> None:
        # One thread owns Playwright, including calls made during the OAuth browser loop.
        playwright = browser = page = None
        try:
            while True:
                task = self._browser_tasks.get()
                if task is None:
                    return
                method, path, body, future = task
                try:
                    if playwright is None:
                        from playwright.sync_api import sync_playwright
                        playwright = sync_playwright().start()
                    if browser is None or not browser.is_connected():
                        # macOS Chromium uses native windows rather than X11 DISPLAY.
                        headless = self.browser_mode == "headless" and os.getenv("CPA_VIRTUAL_DISPLAY") != "1" and sys.platform != "darwin"
                        channel = "chrome" if sys.platform == "darwin" else self.browser_channel
                        options = {"headless": headless}
                        if channel:
                            options["channel"] = channel
                        browser = playwright.chromium.launch(**options)
                        page = None
                    if page is None or page.is_closed():
                        page = browser.new_page(viewport={"width": 1280, "height": 800})
                        self._prepare_cpa_page(page)
                    result = self._fetch_from_page(page, method, path, body)
                    future.set_result(result)
                except CPAAPIError as exc:
                    future.set_exception(exc)
                except Exception:
                    # Do not expose Playwright call logs containing headers or payloads.
                    future.set_exception(CPAAPIError(0, "CPA 浏览器请求失败，请检查管理页面、网络和浏览器安装"))
                    if page is not None:
                        try:
                            page.close()
                        except Exception:
                            pass
                    page = None
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if playwright is not None:
                try:
                    playwright.stop()
                except Exception:
                    pass

    def _prepare_cpa_page(self, page: Any) -> None:
        page.goto(self.base + "/management.html", wait_until="domcontentloaded", timeout=60000)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            text = page.locator("body").inner_text().lower() + page.title().lower()
            if not any(marker in text for marker in ("just a moment", "请稍候", "正在进行安全验证", "verify you are human")):
                self._check_cpa_origin(page.url)
                return
            page.wait_for_timeout(1000)
        page.close()
        raise CPAAPIError(403, "CPA 管理页面的 Cloudflare 校验未完成，请检查站点访问规则")

    def _check_cpa_origin(self, url: str) -> None:
        def origin(raw: str) -> tuple:
            parsed = urllib.parse.urlsplit(raw)
            return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        if origin(url) != origin(self.base):
            raise CPAAPIError(0, "CPA 管理页面跳转到其他站点，已停止发送管理密钥")

    def _fetch_from_page(self, page: Any, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        self._check_cpa_origin(page.url)
        target = self.base + path
        self._check_cpa_origin(target)
        result = page.evaluate(
            """async ({url, method, body, headers}) => {
                const response = await fetch(url, {
                    method, headers, mode: 'same-origin', redirect: 'error',
                    body: body == null ? undefined : JSON.stringify(body)
                });
                return {status: response.status, text: await response.text()};
            }""",
            {"url": target, "method": method, "body": body, "headers": self.headers},
        )
        status, text = int(result["status"]), str(result.get("text", ""))
        if not 200 <= status < 300:
            raise self._http_error(status, text)
        try:
            return json.loads(text) if text else {}
        except ValueError:
            raise CPAAPIError(status, "CPA 返回的内容不是 JSON，请检查管理页面是否仍停留在 Cloudflare 校验页") from None

    def _http_error(self, status: int, detail: str) -> CPAAPIError:
        host = urllib.parse.urlsplit(self.base).netloc
        if status == 401:
            message = f"CPA 管理认证失败（401）：请检查 CPA_MANAGEMENT_KEY；目标地址：{host}"
        elif status == 403 and any(marker in detail.lower() for marker in ("cloudflare", "browser_signature_banned")):
            message = f"请求被 Cloudflare 拦截（403）；目标地址：{host}，浏览器会话未获放行"
        elif status == 403:
            message = f"管理请求被拒绝（403）；目标地址：{host}，请检查 CPA 远程管理和反向代理策略"
        else:
            message = f"CPA API 返回 HTTP {status}；目标地址：{host}"
        error = CPAAPIError(status, message)
        if status == 500:
            try:
                response = json.loads(detail)
                error.upstream_auth_failure = bool(AUTH_FAILURE.search(str(response.get("error", ""))))
            except (ValueError, AttributeError):
                pass
        return error

    def close(self) -> None:
        with self._browser_lock:
            self._closed = True
            if self._browser_thread is not None:
                self._browser_tasks.put(None)
        if self._browser_thread is not None:
            self._browser_thread.join()

    def credentials(self) -> list[dict[str, Any]]:
        return self.request("GET", "/v8/management/credentials").get("files", [])

    def start_oauth(self) -> dict[str, Any]:
        return self.request("GET", "/v8/management/oauth/auth-url?provider=codex")

    def oauth_status(self, state: str) -> dict[str, Any]:
        return self.request("GET", "/v8/management/oauth/status?state=" + urllib.parse.quote(state))

    def callback(self, redirect_url: str) -> dict[str, Any]:
        # CPA accepts the complete browser callback URL and extracts code/state itself.
        return self.request("POST", "/v8/management/oauth/callback", {"provider": "codex", "redirect_url": redirect_url})

    def delete(self, name: str) -> dict[str, Any]:
        return self.request("DELETE", "/v8/management/credentials?name=" + urllib.parse.quote(name))

    def refresh(self, name: str) -> dict[str, Any]:
        return self.request("POST", "/v8/management/credentials/refresh", {"name": name})

    def usage(self, credential: dict[str, Any]) -> dict[str, Any]:
        """Ask CPA to query the Codex usage endpoint with the selected credential."""
        auth_index = credential.get("auth_index") or credential.get("authIndex")
        if not auth_index:
            raise CPAAPIError(0, "凭据缺少 auth_index")
        token_claims = credential.get("id_token") if isinstance(credential.get("id_token"), dict) else {}
        header = {
            "Authorization": "Bearer $TOKEN$",
            "Content-Type": "application/json",
            "User-Agent": "codex-tui/0.149.1",
        }
        account_id = token_claims.get("chatgpt_account_id") or token_claims.get("chatgptAccountId")
        if account_id:
            header["Chatgpt-Account-Id"] = str(account_id)
        response = self.request("POST", "/v8/management/requests/api-call", {
            "auth_index": str(auth_index),
            "method": "GET",
            "url": "https://chatgpt.com/backend-api/wham/usage",
            "header": header,
            "data": "",
        })
        status = int(response.get("status_code") or 0)
        if status >= 400:
            error = CPAAPIError(status, f"Codex 额度接口返回 HTTP {status}")
            raise error
        body = response.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError as exc:
                raise CPAAPIError(status, "Codex 额度接口返回了无效 JSON") from exc
        if not isinstance(body, dict):
            raise CPAAPIError(status, "Codex 额度接口返回格式无效")
        return body


class AccountDeletedError(RuntimeError):
    """The upstream OpenAI account was deleted or deactivated."""


class LoginAutomation:
    def __init__(self, cpa: CPAClient, log, browser_channel: str = "chromium", two_factor: TwoFactorConfig | None = None):
        self.cpa = cpa
        self.log = log
        self.browser_channel = browser_channel
        self.two_factor = TwoFactorProvider(two_factor)

    def _info(self, message: str, level: str = "info") -> None:
        self.log(message, level)

    def run(self, account: Account, headless: bool = False) -> dict[str, Any]:
        self._info(f"[{account.email}] 开始检查 CPA 凭据")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("请先安装浏览器依赖：pip install -r requirements.txt && playwright install chromium") from exc

        self._refresh_or_remove_matching(account)
        self._info(f"[{account.email}] 正在创建 OAuth 会话")
        start = self.cpa.start_oauth()
        state = start["state"]
        callback_data: dict[str, str] = {}
        callback_seen = threading.Event()
        mfa_submitted = False
        consent_submitted = False

        def handle_callback(url: str) -> None:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            code = query.get("code", [""])[0]
            if code:
                callback_data.update(state=query.get("state", [state])[0], code=code, redirect_url=url)
                callback_seen.set()

        with sync_playwright() as playwright:
            virtual_display = headless and os.getenv("CPA_VIRTUAL_DISPLAY") == "1"
            launch_options = {"headless": False if virtual_display else headless}
            if virtual_display:
                self._info(f"[{account.email}] 使用 Xvfb 虚拟显示器运行 headed Chrome")
            if self.browser_channel:
                launch_options["channel"] = self.browser_channel
            browser = playwright.chromium.launch(**launch_options)
            context = browser.new_context()
            page = context.new_page()
            active_page = [page]

            def bind_page(candidate: Any) -> None:
                active_page[0] = candidate
                candidate.on("request", lambda request: handle_callback(request.url) if request.is_navigation_request() else None)
                candidate.on("framenavigated", lambda frame: (self._info(f"[{account.email}] 页面跳转：{frame.url}"), handle_callback(frame.url)) if frame == candidate.main_frame else None)
                candidate.on("close", lambda: self._info(f"[{account.email}] OAuth 页面已关闭"))

            bind_page(page)
            context.on("page", bind_page)
            try:
                self._info(f"[{account.email}] 已打开 OpenAI 登录页面")
                page.goto(start["url"], wait_until="domcontentloaded")
            except Exception:
                # The OAuth redirect points to localhost:1455; CPA may receive it through
                # the browser URL even when no local callback listener is running.
                pass
            self._wait_for_login_page(page, account.email)
            self._fill_login(page, account, context)
            deadline = time.time() + 180
            while time.time() < deadline and not callback_seen.is_set():
                page = active_page[0]
                if page.is_closed():
                    open_pages = [candidate for candidate in context.pages if not candidate.is_closed()]
                    if not open_pages:
                        raise RuntimeError("OAuth 浏览器页面已关闭")
                    page = open_pages[-1]
                    active_page[0] = page
                    bind_page(page)
                    self._info(f"[{account.email}] 已切换到新的 OAuth 页面")
                handle_callback(page.url)
                if self._is_account_deleted(page):
                    raise AccountDeletedError("账号已删除或停用")
                if self._looks_like_mfa(page) and not mfa_submitted:
                    self._fill_mfa(page, self.two_factor.code(account.totp_secret))
                    mfa_submitted = True
                    self._info(f"[{account.email}] 2FA 验证码已自动填写并提交（{'本地 TOTP' if self.two_factor.config.mode == 'local' else '配置的 2FA 接口'}）")
                if self._looks_like_consent(page) and not consent_submitted:
                    self._submit_consent(page)
                    consent_submitted = True
                    self._info(f"[{account.email}] 已自动确认 Codex 授权")
                page.wait_for_timeout(500)
            if not callback_seen.is_set():
                raise RuntimeError("登录未在 180 秒内完成；可能需要人工处理 CAPTCHA 或额外验证")
            self._info(f"[{account.email}] 已捕获 OAuth 回调")
            browser.close()

        callback_url = callback_data["redirect_url"]
        self.cpa.callback(callback_url)
        self._info(f"[{account.email}] 完整回调地址已提交 CPA，等待凭据落盘")
        deadline = time.time() + 60
        while time.time() < deadline:
            status = self.cpa.oauth_status(state)
            if status.get("status") == "ok":
                self._info(f"[{account.email}] 认证成功")
                return status
            if status.get("status") == "error":
                raise RuntimeError(status.get("error", "CPA OAuth failed"))
            time.sleep(1)
        raise RuntimeError("CPA OAuth 会话超时")

    def _refresh_or_remove_matching(self, account: Account) -> None:
        email = account.email.lower()
        for item in matching_credentials(account.email, self.cpa.credentials()):
            name = str(item.get("name") or item.get("id") or "")
            try:
                self._info(f"[{account.email}] 检查凭据 {name}")
                self.cpa.refresh(name)
                self._info(f"[{account.email}] 现有凭据刷新成功")
            except RuntimeError as exc:
                message = str(exc).lower()
                rejected = exc.upstream_auth_failure if isinstance(exc, CPAAPIError) else bool(AUTH_FAILURE.search(message))
                if rejected:
                    self._info(f"[{account.email}] 凭据 {name} 返回 401，正在删除")
                    self.cpa.delete(name)
                    self._info(f"[{account.email}] 已删除失效凭据")
                else:
                    raise

    def _wait_for_login_page(self, page: Any, email: str) -> None:
        # Cloudflare may hold the page for a while; wait instead of submitting into a stale page.
        deadline = time.time() + 90
        last_wait_log = 0.0
        while time.time() < deadline:
            if self._find_visible(page, 'input[type="email"], input[name="email"], input[autocomplete="username"]'):
                self._info(f"[{email}] 登录表单已就绪")
                return
            now = time.time()
            if now - last_wait_log >= 5:
                self._info(f"[{email}] 正在等待 Cloudflare 校验")
                last_wait_log = now
            page.wait_for_timeout(1000)
        raise RuntimeError("OpenAI 登录页面或 Cloudflare 校验超过 90 秒未就绪")

    def _fill_login(self, page: Any, account: Account, context: Any | None = None) -> None:
        email_selector = 'input[type="email"], input[name="email"], input[autocomplete="username"]'
        email, email_page = self._find_visible_page(page, email_selector, context)
        if email is None:
            raise RuntimeError("未找到 OpenAI 邮箱输入框")
        email.fill(account.email)
        button = self._find_visible(email_page, 'button[type="submit"]')
        if button is not None:
            button.click()
        else:
            email.press("Enter")

        password_selector = 'input[type="password"], input[name="password"], input[autocomplete="current-password"]'
        deadline = time.time() + 90
        last_wait_log = 0.0
        password = None
        while time.time() < deadline:
            password, password_page = self._find_visible_page(email_page, password_selector, context)
            if password is not None:
                break
            pages = [email_page]
            if context is not None:
                pages = [candidate for candidate in context.pages if not candidate.is_closed()]
            if any(self._has_text(candidate, "Operation timed out") or self._has_text(candidate, "糟糕，出错了") for candidate in pages):
                raise RuntimeError("OpenAI 登录页面请求超时")
            now = time.time()
            if now - last_wait_log >= 5:
                current_url = password_page.url if password_page is not None else email_page.url
                self._info(f"[{account.email}] 邮箱已提交，等待密码页面（当前页面：{current_url[:160]}）")
                last_wait_log = now
            email_page.wait_for_timeout(1000)
        if password is None:
            raise RuntimeError("提交邮箱后未出现密码输入框，可能卡在 Cloudflare 校验或登录页未完成跳转")

        password.fill(account.password)
        button = self._find_visible(password_page, 'button[type="submit"]')
        if button is not None:
            button.click()
        else:
            password.press("Enter")
        self._info(f"[{account.email}] 邮箱和密码已自动填写并提交")

    @staticmethod
    def _find_visible(page: Any, selector: str) -> Any | None:
        """Find a visible control in the main page or an OAuth iframe."""
        frames = [page, *getattr(page, "frames", [])]
        for frame in frames:
            try:
                locator = frame.locator(selector).first
                if locator.count() and locator.is_visible():
                    return locator
            except Exception:
                continue
        return None

    @classmethod
    def _find_visible_page(cls, page: Any, selector: str, context: Any | None = None) -> tuple[Any | None, Any | None]:
        pages = [page]
        if context is not None:
            pages = [candidate for candidate in context.pages if not candidate.is_closed()]
            if page in pages:
                pages.remove(page)
            pages.insert(0, page)
        for candidate in pages:
            locator = cls._find_visible(candidate, selector)
            if locator is not None:
                return locator, candidate
        return None, None

    @staticmethod
    def _has_text(page: Any, text: str) -> bool:
        try:
            return text.lower() in page.locator("body").inner_text().lower()
        except Exception:
            return False

    @staticmethod
    def _is_account_deleted(page: Any) -> bool:
        try:
            text = page.locator("body").inner_text().lower()
        except Exception:
            return False
        markers = (
            "你没有账户，因为该账户已被删除或停用",
            "该账户已被删除或停用",
            "account has been deleted or deactivated",
            "because this account has been deleted",
            "account was deleted or deactivated",
        )
        return any(marker in text for marker in markers)

    @staticmethod
    def _looks_like_consent(page: Any) -> bool:
        return "/sign-in-with-chatgpt/codex/consent" in page.url

    @staticmethod
    def _submit_consent(page: Any) -> None:
        button = page.locator('button[type="submit"]').first
        if button.count():
            button.click()
            return
        button = page.get_by_role("button", name="继续").first
        if button.count():
            button.click()
            return
        raise RuntimeError("未找到 Codex 授权确认按钮")

    @staticmethod
    def _looks_like_mfa(page: Any) -> bool:
        return page.locator('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name="code"], input[name*="otp" i]').count() > 0 or "mfa-challenge" in page.url

    @staticmethod
    def _fill_mfa(page: Any, code: str) -> None:
        field = page.locator('input[autocomplete="one-time-code"], input[inputmode="numeric"], input[name="code"], input[name*="otp" i]').first
        if field.count():
            field.fill(code)
            button = page.locator('button[type="submit"]').first
            if button.count():
                button.click()
            else:
                field.press("Enter")


class Handler(BaseHTTPRequestHandler):
    client: CPAClient
    automation: LoginAutomation
    config: Config
    account_map: dict[str, Account]
    account_status: dict[str, str]
    config_path: Path
    log_lock = threading.Lock()
    logs: deque[dict[str, Any]] = deque(maxlen=500)
    log_seq = 0
    auth_lock = threading.RLock()
    login_executor: ThreadPoolExecutor
    login_futures: dict[str, Future]
    batch_running = False
    auto_reauth = False
    state_store = None
    monitor_stop = threading.Event()
    monitor_wakeup = threading.Event()
    scan_lock = threading.Lock()
    quota_cache = None
    admin_auth = None
    deletion_running = False

    @classmethod
    def log(cls, message: str, level: str = "info") -> None:
        with cls.log_lock:
            cls.log_seq += 1
            cls.logs.append({"id": cls.log_seq, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "level": level, "message": message})

    @classmethod
    def save_account(cls, account: Account) -> None:
        path = cls.config.accounts_file
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        replacement = f"{account.email}----{account.password}----{account.totp_secret}"
        replaced = False
        output: list[str] = []
        for raw in lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                output.append(raw)
                continue
            parts = stripped.split("----", 2)
            if parts and parts[0].strip().lower() == account.email.lower():
                output.append(replacement)
                replaced = True
            else:
                output.append(raw)
        if not replaced:
            output.append(replacement)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
        temp.replace(path)

    def _json(self, status: int, data: Any, headers=None) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, str(value))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 65536:
            raise ValueError("request body is too large")
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("request body must be an object")
        return body

    def _session_token(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == SESSION_COOKIE:
                return value
        return ""

    def _authenticated(self) -> bool:
        return self.admin_auth is not None and self.admin_auth.authenticated(self._session_token())

    def _require_auth(self, api=False) -> bool:
        if self._authenticated():
            return True
        if api:
            self._json(401, {"error": "请先登录管理员账号"})
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        return False

    def _serve_static(self, name, content_type):
        raw = (STATIC / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _session_cookie(self, token):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() == "https" else ""
        return f"{SESSION_COOKIE}={token}; Max-Age={SESSION_SECONDS if token else 0}; HttpOnly; SameSite=Strict; Path=/" + secure

    def _same_origin_request(self):
        origin = self.headers.get("Origin")
        same_origin = not origin or urllib.parse.urlsplit(origin).netloc == self.headers.get("Host")
        if (not same_origin or self.headers.get("Sec-Fetch-Site") == "cross-site"
                or self.headers.get("X-CPA-Request") != "1"):
            self._json(403, {"error": "请求来源校验失败，请刷新页面后重试"})
            return False
        return True

    def _effective_status(self, email: str, files: list[dict[str, Any]]) -> str:
        remote_status = self._status_for(email, files)
        local_status = self.account_status.get(email)
        if local_status in {"queued", "pending", "deleted", "error", "paused"}:
            return local_status
        # CPA is authoritative for active/missing/invalid. Local error is only transient.
        return remote_status if remote_status != "unknown" else (local_status or "unknown")

    def _scan_auto_reauth(self, files: list[dict[str, Any]]) -> None:
        if not self.auto_reauth or self.batch_running or self.deletion_running or not self.scan_lock.acquire(blocking=False):
            return
        try:
            for account in list(self.account_map.values()):
                if not self.auto_reauth:
                    break
                # An authentication failure needs manual review, not an automatic retry loop.
                if self.account_status.get(account.email) in {"error", "deleted", "paused", "queued", "pending"}:
                    continue
                if self._status_for(account.email, files) not in {"missing", "invalid"}:
                    continue
                if self._launch_login(account.email):
                    self.log(f"[{account.email}] 自动重新认证已加入队列")
        finally:
            self.scan_lock.release()

    def _credential_row(self, serial: int, account: Account, files: list[dict[str, Any]]) -> dict[str, Any]:
        return account_summary(serial, account.email, files, self._effective_status(account.email, files))

    def _enrich_quota(self, row: dict[str, Any], files: list[dict[str, Any]]) -> dict[str, Any]:
        if row["status"] not in {"active", "unavailable"} or self.quota_cache is None:
            return row
        credential = selected_credential(row["email"], files)
        if not credential:
            return row
        cached = self.quota_cache.get(credential)
        # A newer passive observation takes precedence over an older cache entry.
        if cached.get("quota_observed_at") and row.get("quota_observed_at"):
            if row["quota_observed_at"] > cached["quota_observed_at"]:
                cached = {key: value for key, value in cached.items() if key in {"quota_loading", "quota_error"}}
        return {**row, **cached}

    def _settings(self) -> dict[str, Any]:
        return {"auto_reauth": self.auto_reauth, "auth_concurrency": self.config.auth_concurrency,
                "auto_reauth_interval": self.config.auto_reauth_interval,
                "cpa_host": urllib.parse.urlsplit(self.client.base).netloc,
                "transport": "browser" if self.client.browser_transport else "http"}

    def _monitor_loop(self) -> None:
        while not self.monitor_stop.is_set():
            if self.auto_reauth:
                try:
                    self._scan_auto_reauth(self.client.credentials())
                except Exception as exc:
                    self.log(f"自动检查 CPA 失败：{exc}", "error")
            self.monitor_wakeup.wait(self.config.auto_reauth_interval)
            self.monitor_wakeup.clear()

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path in {"/login", "/login.html"}:
            return self._serve_static("login.html", "text/html")
        if path == "/login.js":
            return self._serve_static("login.js", "text/javascript")
        if path == "/remember-password.js":
            return self._serve_static("remember-password.js", "text/javascript")
        if path == "/style.css":
            return self._serve_static("style.css", "text/css")
        if path == "/api/auth/status":
            return self._json(200, {"authenticated": self._authenticated(), **(self.admin_auth.status() if self.admin_auth else {})})
        if path in {"/app.js", "/"} or path.startswith("/api/"):
            if not self._require_auth(api=path.startswith("/api/")):
                return
        if path == "/api/logs":
            try:
                since = int(urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("since", [0])[0])
            except ValueError:
                since = 0
            with self.log_lock:
                return self._json(200, {"logs": [entry for entry in self.logs if entry["id"] > since], "last_id": self.log_seq})
        if path == "/api/accounts":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                page = max(1, int(query.get("page", [1])[0]))
                allowed_sizes = PAGE_SIZES
                requested_size = int(query.get("page_size", [10])[0])
                page_size = requested_size if requested_size in allowed_sizes else 10
                files = self.client.credentials()
                accounts = list(self.account_map.values())
                all_rows = [self._credential_row(index + 1, account, files) for index, account in enumerate(accounts)]
                counts = {status: sum(row["status"] == status for row in all_rows) for status in {row["status"] for row in all_rows}}
                search = query.get("q", [""])[0].strip().lower()
                selected_status = query.get("status", [""])[0]
                filtered = [row for row in all_rows if (not search or search in row["email"].lower()) and (not selected_status or selected_status == row["status"])]
                if query.get("selection") == ["all"]:
                    return self._json(200, {"emails": [row["email"] for row in filtered], "total": len(filtered)})
                total = len(filtered)
                page = min(page, max(1, (total + page_size - 1) // page_size))
                start = (page - 1) * page_size
                rows = filtered[start:start + page_size]
                rows = [self._enrich_quota(row, files) for row in rows]
                return self._json(200, {"items": rows, "total": total, "page": page, "page_size": page_size,
                                      "has_more": start + len(rows) < total, "counts": counts, "configured_total": len(accounts)})
            except (TypeError, ValueError):
                return self._json(400, {"error": "page/page_size 参数无效"})
            except Exception as exc:
                self.log(f"CPA 状态刷新失败：{exc}", "error")
                return self._json(502, {"error": str(exc)})
        if path == "/api/settings":
            return self._json(200, self._settings())
        static_files = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
        if path in static_files:
            name, content_type = static_files[path]
            return self._serve_static(name, content_type)
        self.send_error(404)

    def _launch_login(self, email: str) -> bool:
        account = self.account_map.get(email)
        if not account:
            return False
        with self.auth_lock:
            if self.deletion_running:
                return False
            current = self.account_status.get(email)
            if current in {"deleted", "pending", "queued"}:
                self.log(f"[{email}] 跳过认证，当前状态：{current}")
                return False
        if current == "active":
            try:
                if self._status_for(email, self.client.credentials()) == "active":
                    self.log(f"[{email}] 跳过认证，CPA 状态正常")
                    return False
            except Exception as exc:
                self.log(f"[{email}] 检查 CPA 状态失败：{exc}", "error")
                return False
        # Reserve the account before submitting so duplicate clicks cannot start another flow.
        with self.auth_lock:
            if self.deletion_running or self.account_status.get(email) in {"deleted", "pending", "queued"}:
                return False
            self.account_status[email] = "queued"
            self.log(f"[{email}] 已加入认证队列")
            try:
                self.login_futures[email] = self.login_executor.submit(self._run_login, account)
            except Exception:
                self.account_status[email] = "error"
                raise
        return True

    def _run_login(self, account: Account) -> None:
        email = account.email
        with self.auth_lock:
            self.account_status[email] = "pending"
        self.log(f"[{email}] 已开始后台登录任务")
        try:
            self.automation.run(account, self.config.browser_headless)
            with self.auth_lock:
                self.account_status[email] = "active"
        except AccountDeletedError as exc:
            with self.auth_lock:
                self.account_status[email] = "deleted"
            self.log(f"[{email}] 账号已删除：{exc}", "error")
        except Exception as exc:
            with self.auth_lock:
                self.account_status[email] = "error"
            self.log(f"[{email}] 认证失败：{exc}", "error")
        finally:
            if self.state_store:
                try:
                    self.state_store.account_result(email, self.account_status[email])
                except OSError:
                    self.log(f"[{email}] 无法保存账号状态，请检查 data 目录写入权限", "error")

    def _run_batch_auth(self, targets: list[str]) -> None:
        self.log(f"批量认证并发数：{self.config.auth_concurrency}")
        try:
            futures = []
            for email in targets:
                if self._launch_login(email):
                    futures.append(self.login_futures[email])
            for future in as_completed(futures):
                future.result()
            self.log("批量认证任务完成")
        except Exception as exc:
            self.log(f"批量认证调度失败：{exc}", "error")
        finally:
            with self.auth_lock:
                type(self).batch_running = False

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/auth/login":
            if self.admin_auth is None:
                return self._json(503, {"error": "管理员登录尚未初始化"})
            if not self._same_origin_request():
                return
            try:
                password = self._body().get("password")
                if not isinstance(password, str) or not password:
                    return self._json(400, {"error": "请输入管理员密码"})
                token, data, status = self.admin_auth.login(password)
                if token:
                    self.log("管理员登录成功")
                    return self._json(status, data, {"Set-Cookie": self._session_cookie(token)})
                return self._json(status, data, {"Retry-After": data["retry_after"]} if data.get("retry_after") else {})
            except (TypeError, ValueError, json.JSONDecodeError):
                return self._json(400, {"error": "登录请求格式无效"})
            except OSError:
                return self._json(503, {"error": "无法保存登录保护状态，请检查 data 目录写入权限"})
        if not self._require_auth(api=True):
            return
        if self.admin_auth is not None and not self._same_origin_request():
            return
        if path == "/api/auth/logout":
            self.admin_auth.logout(self._session_token())
            return self._json(200, {"ok": True}, {"Set-Cookie": self._session_cookie("")})
        if path == "/api/settings":
            try:
                enabled = self._body().get("auto_reauth")
                if type(enabled) is not bool:
                    return self._json(400, {"error": "auto_reauth 必须是布尔值"})
                if self.state_store:
                    self.state_store.set_enabled(enabled)
                type(self).auto_reauth = enabled
                self.monitor_wakeup.set()
                self.log("自动重新认证已" + ("开启" if enabled else "关闭"))
                return self._json(200, self._settings())
            except OSError:
                return self._json(500, {"error": "无法保存开关，请检查 data 目录写入权限"})
            except (ValueError, TypeError):
                return self._json(400, {"error": "设置格式无效"})
        if path == "/api/accounts":
            try:
                body = self._body()
                account = Account(str(body["email"]).strip(), str(body["password"]), str(body["totp_secret"]).strip())
                if not account.email or not account.password or not account.totp_secret:
                    raise ValueError("email、password、totp_secret 都不能为空")
                self.save_account(account)
                self.account_map[account.email] = account
                self.account_status.pop(account.email, None)
                type(self).config = replace(self.config, accounts=tuple(self.account_map.values()))
                if self.state_store:
                    self.state_store.account_result(account.email, "active")
                self.log(f"[{account.email}] 账号配置已保存")
                return self._json(200, {"ok": True})
            except Exception as exc:
                self.log(f"保存账号失败：{exc}", "error")
                return self._json(500, {"error": f"保存失败：{exc}"})
        if path in {"/api/delete", "/api/delete-all"}:
            try:
                body = self._body()
                requested = [body["email"]] if path == "/api/delete" and "email" in body else body.get("emails")
                if not isinstance(requested, list) or not requested or not all(isinstance(email, str) and email.strip() for email in requested):
                    raise ValueError("请选择要删除的账号")
                configured = {email.lower(): email for email in self.account_map}
                if any(email.strip().lower() not in configured for email in requested):
                    raise ValueError("只能删除账号配置列表中的 CPA 凭证")
                emails = list(dict.fromkeys(configured[email.strip().lower()] for email in requested))
            except (ValueError, TypeError):
                return self._json(400, {"error": "请选择有效的配置账号；未选择时不会执行删除"})
            return self._delete_credentials(emails)
        if path == "/api/login-all":
            with self.auth_lock:
                if self.deletion_running or self.batch_running or any(status in {"queued", "pending"} for status in self.account_status.values()):
                    return self._json(409, {"error": "已有批量或单账号认证任务正在运行"})
                type(self).batch_running = True
            try:
                files = self.client.credentials()
                targets: list[str] = []
                skipped: list[dict[str, str]] = []
                for account in self.account_map.values():
                    status = self._effective_status(account.email, files)
                    if status in {"active", "deleted", "pending", "queued"}:
                        skipped.append({"email": account.email, "status": status})
                    else:
                        targets.append(account.email)
            except Exception as exc:
                with self.auth_lock:
                    type(self).batch_running = False
                self.log(f"批量认证读取 CPA 状态失败：{exc}", "error")
                return self._json(502, {"error": str(exc)})

            if not targets:
                with self.auth_lock:
                    type(self).batch_running = False
                self.log("批量认证没有待处理账号")
                return self._json(200, {"ok": True, "started": 0, "skipped": skipped})

            self.log(f"批量认证开始，共 {len(targets)} 个账号；跳过 {len(skipped)} 个账号")
            threading.Thread(target=self._run_batch_auth, args=(targets,), daemon=True).start()
            return self._json(202, {"ok": True, "started": len(targets), "skipped": skipped, "concurrency": self.config.auth_concurrency})
        if path != "/api/login":
            self.send_error(404)
            return
        email = str(self._body().get("email", "")).strip()
        if not self._launch_login(email):
            if email not in self.account_map:
                return self._json(404, {"error": "account is not configured"})
            return self._json(409, {"error": f"account status is {self.account_status.get(email)}"})
        return self._json(202, {"ok": True, "status": "started"})

    def _delete_credentials(self, emails):
        with self.auth_lock:
            if self.deletion_running or self.batch_running or any(value in {"queued", "pending"} for value in self.account_status.values()):
                return self._json(409, {"error": "请等待正在进行的认证或删除操作完成"})
            type(self).deletion_running = True
        try:
            files = self.client.credentials()
            deleted, failed, processed, missing = [], [], [], []
            seen = set()
            for email in emails:
                credentials = matching_credentials(email, files)
                email_failed = False
                if not credentials:
                    missing.append(email)
                for credential in credentials:
                    name = str(credential.get("name") or credential.get("id") or "")
                    if name in seen:
                        continue
                    seen.add(name)
                    try:
                        self.client.delete(name)
                        deleted.append(name)
                        # Pause immediately after the first deletion, including partial failures.
                        if self.account_status.get(email) != "deleted":
                            self.account_status[email] = "paused"
                        self.log(f"[{email}] 已删除 CPA 凭证：{name}")
                    except Exception as exc:
                        email_failed = True
                        failed.append({"email": email, "name": name, "error": str(exc)})
                        self.log(f"[{email}] 删除 CPA 凭证失败：{exc}", "error")
                if not email_failed:
                    processed.append(email)
                    if self.account_status.get(email) != "deleted":
                        self.account_status[email] = "paused"
                if self.account_status.get(email) in {"paused", "deleted"} and self.state_store:
                    try:
                        self.state_store.account_result(email, self.account_status[email])
                    except OSError:
                        failed.append({"email": email, "error": "凭据操作已完成，但暂停状态保存失败，请检查 data 目录权限"})
            self.log(f"删除完成：{len(deleted)} 个凭证，{len(failed)} 个错误")
            return self._json(200, {"ok": not failed, "deleted": deleted, "failed": failed, "processed_emails": processed, "missing": missing})
        except Exception as exc:
            self.log(f"删除读取 CPA 凭证失败：{exc}", "error")
            return self._json(502, {"error": str(exc)})
        finally:
            with self.auth_lock:
                type(self).deletion_running = False

    @staticmethod
    def _status_for(email: str, files: list[dict[str, Any]]) -> str:
        return credential_status(email, files)


def main() -> None:
    parser = argparse.ArgumentParser(description="CLIProxyAPI Codex OAuth helper")
    parser.add_argument("--config", default=os.getenv("CPA_HELPER_CONFIG", str(ROOT / "config.json")))
    args = parser.parse_args()
    config_path = Path(args.config).expanduser().resolve()
    load_dotenv(config_path.parent / ".env")
    load_dotenv(Path.cwd() / ".env")
    config = load_config(config_path)
    Handler.admin_auth = AdminAuth(config.admin_password, config_path.parent / "data" / "admin_auth.json")
    Handler.config = config
    Handler.config_path = config_path
    Handler.client = CPAClient(config.cpa_url, config.management_key, config.browser_mode, config.browser_channel)
    Handler.automation = LoginAutomation(Handler.client, Handler.log, config.browser_channel, config.two_factor)
    Handler.quota_cache = QuotaCache(Handler.client.usage, Handler.log)
    Handler.account_map = {account.email: account for account in config.accounts}
    Handler.account_status = {}
    Handler.state_store = RuntimeState(config_path.parent / "data" / "state.json", config.auto_reauth)
    Handler.account_status.update(Handler.state_store.accounts)
    Handler.auto_reauth = Handler.state_store.auto_reauth
    Handler.login_futures = {}
    Handler.login_executor = ThreadPoolExecutor(max_workers=config.auth_concurrency, thread_name_prefix="oauth")
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), Handler)
    controller = object.__new__(Handler)
    monitor = threading.Thread(target=controller._monitor_loop, daemon=True, name="auto-reauth")
    monitor.start()
    address = f"http://{config.listen_host}:{config.listen_port}/"
    Handler.log(f"服务已启动，CPA 地址：{config.cpa_url}")
    print(f"CPA Codex Login Helper: {address}", flush=True)
    if config.open_browser and config.listen_host in {"127.0.0.1", "localhost"}:
        webbrowser.open(address)
    Handler.log("CPA 连接方式：" + ("浏览器同源 API（复用会话）" if Handler.client.browser_transport else "直接 HTTP API"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        Handler.monitor_stop.set()
        Handler.monitor_wakeup.set()
        monitor.join()
        server.server_close()
        Handler.login_executor.shutdown(wait=True)
        if Handler.quota_cache is not None:
            Handler.quota_cache.close()
        Handler.client.close()


if __name__ == "__main__":
    main()
