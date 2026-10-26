"""Single-admin sessions and durable progressive login throttling."""
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from pathlib import Path

SESSION_COOKIE = 'cpa_admin_session'
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 210000
INITIAL_FAILURE_LIMIT = 3
COOLDOWN_SECONDS = (60, 180, 600, 3600, 86400)


class AdminAuth:
    def __init__(self, password, path, clock=time.time):
        if not isinstance(password, str) or not password:
            raise ValueError('ADMIN_PASSWORD or server.admin_password is required')
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.RLock()
        self.salt = secrets.token_bytes(16)
        self.digest = self._password_digest(password)
        self.failures = 0
        self.blocked_until = 0
        self.sessions = {}
        if self.path.exists():
            saved = json.loads(self.path.read_text(encoding='utf-8'))
            failures, until = saved.get('failures', 0), saved.get('blocked_until', 0)
            if type(failures) is not int or failures < 0 or not isinstance(until, (int, float)) or not math.isfinite(until) or until < 0:
                raise ValueError('invalid administrator login throttle state')
            self.failures, self.blocked_until = failures, until

    def _password_digest(self, password):
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), self.salt, PASSWORD_ITERATIONS)

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.tmp')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump({'failures': self.failures, 'blocked_until': self.blocked_until}, output)
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)

    def status(self):
        with self.lock:
            return {'retry_after': max(0, math.ceil(self.blocked_until - self.clock()))}

    def login(self, password):
        with self.lock:
            remaining = self.status()['retry_after']
            if remaining:
                return None, {'error': '登录已锁定，请等待冷却结束', 'retry_after': remaining}, 429
            if not hmac.compare_digest(self._password_digest(password), self.digest):
                self.failures += 1
                if self.failures >= INITIAL_FAILURE_LIMIT:
                    level = min(self.failures - INITIAL_FAILURE_LIMIT, len(COOLDOWN_SECONDS) - 1)
                    self.blocked_until = self.clock() + COOLDOWN_SECONDS[level]
                self._save()
                remaining = self.status()['retry_after']
                data = {'error': '管理员密码错误', 'retry_after': remaining,
                        'attempts_remaining': max(0, INITIAL_FAILURE_LIMIT - self.failures)}
                if remaining:
                    data['error'] = '密码错误次数过多，已进入登录冷却'
                return None, data, 429 if remaining else 401
            self.failures, self.blocked_until = 0, 0
            self._save()
            now = self.clock()
            self.sessions = {key: expiry for key, expiry in self.sessions.items() if expiry > now}
            token = secrets.token_urlsafe(32)
            self.sessions[self._token_digest(token)] = now + SESSION_SECONDS
            return token, {'ok': True}, 200

    @staticmethod
    def _token_digest(token):
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def authenticated(self, token):
        if not token:
            return False
        with self.lock:
            key = self._token_digest(token)
            expiry = self.sessions.get(key, 0)
            if expiry <= self.clock():
                self.sessions.pop(key, None)
                return False
            return True

    def logout(self, token):
        if token:
            with self.lock:
                self.sessions.pop(self._token_digest(token), None)
