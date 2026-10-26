"""Non-secret CPA account summaries and durable automation preferences."""
import json
import math
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

PAGE_SIZES = (10, 20, 50, 100, 200, 500)
AUTH_FAILURE = re.compile(r'\b401\b|unauthorized|invalid[_ -]?token|token[_ -]?(expired|revoked)|refresh_token_reused|refresh_token_invalidated', re.I)
DELETED_MARKERS = ('该账户已被删除或停用', 'account has been deleted or deactivated', 'account was deleted or deactivated')
QUOTA_CACHE_SECONDS = 120
QUOTA_ERROR_CACHE_SECONDS = 60


def matching_credentials(email, files):
    email = email.strip().lower()
    matches = []
    for item in files:
        name = str(item.get('name') or item.get('id') or '')
        metadata = str(item.get('email') or item.get('account') or '').strip().lower()
        provider = str(item.get('provider') or item.get('type') or 'codex').lower()
        if provider == 'codex' and email in name.lower() and (not metadata or metadata == email):
            matches.append(item)
    return matches


def credential_status(email, files):
    matches = matching_credentials(email, files)
    if not matches:
        return 'missing'
    usable = [item for item in matches if not item.get('disabled') and item.get('status') != 'disabled']
    if not usable:
        return 'disabled'
    # Quota exhaustion is not an authentication failure.
    if any(item.get('status') == 'active' and not item.get('unavailable') for item in usable):
        return 'active'
    messages = [str(item.get('status_message') or '') for item in usable]
    if any(any(marker in message.lower() for marker in DELETED_MARKERS) for message in messages):
        return 'deleted'
    if any(AUTH_FAILURE.search(message) for message in messages):
        return 'invalid'
    if any(item.get('unavailable') for item in usable):
        return 'unavailable'
    return str(usable[0].get('status') or 'unknown')


def as_timestamp(value):
    if value is None or value == '':
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                return None
            return datetime.fromtimestamp(number, timezone.utc).isoformat()
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def selected_credential(email, files):
    matches = matching_credentials(email, files)
    return max(matches, key=lambda item: (not item.get('disabled'), item.get('status') == 'active' and not item.get('unavailable'), str(item.get('updated_at') or item.get('modtime') or '')), default={})


def window_label(minutes, window):
    if 40320 <= minutes <= 44640:
        return '月额度'
    if minutes == 300:
        return '5 小时'
    if minutes == 10080:
        return '周额度'
    return f'{minutes // 60} 小时' if minutes and minutes % 60 == 0 else f'{minutes:g} 分钟' if minutes else ('主额度' if window == 'primary' else '次额度')


def quota_summary(signals, observed_at):
    signals = {str(key).lower(): value for key, value in signals.items()}
    reset_times, quota = [], []
    for window in ('primary', 'secondary'):
        prefix = 'x-codex-' + window + '-'
        try:
            minutes = float(signals.get(prefix + 'window-minutes') or 0)
            if not math.isfinite(minutes) or minutes < 0:
                minutes = 0
        except (ValueError, TypeError):
            minutes = 0
        if minutes == 0 and signals.get(prefix + 'window-minutes') is not None:
            continue
        label = window_label(minutes, window)
        reset_at = as_timestamp(signals.get(prefix + 'reset-at'))
        if not reset_at and observed_at:
            # Relative resets are anchored to the observation, never to each page refresh.
            try:
                after = float(signals.get(prefix + 'reset-after-seconds'))
                if math.isfinite(after) and after >= 0:
                    reset_at = as_timestamp(datetime.fromisoformat(observed_at).timestamp() + after)
            except (TypeError, ValueError, OverflowError):
                pass
        if reset_at:
            reset_times.append({'window': window, 'label': label, 'reset_at': reset_at})
        try:
            percent = float(signals.get(prefix + 'used-percent'))
            if not math.isfinite(percent) or not 0 <= percent <= 100:
                continue
        except (ValueError, TypeError):
            continue
        quota.append({'window': window, 'label': label, 'used_percent': percent, 'reset_at': reset_at})
    return {'reset_times': reset_times, 'quota': quota, 'quota_observed_at': observed_at}


def usage_summary(payload, observed_at):
    rate = payload.get('rate_limit', payload.get('rateLimit')) or {}
    if not isinstance(rate, dict):
        raise ValueError('invalid quota rate_limit')
    signals = {}
    for name in ('primary', 'secondary'):
        window = rate.get(name + '_window', rate.get(name + 'Window'))
        if not isinstance(window, dict):
            continue
        prefix = 'x-codex-' + name + '-'
        for target, snake, camel in (('used-percent', 'used_percent', 'usedPercent'), ('reset-at', 'reset_at', 'resetAt'), ('reset-after-seconds', 'reset_after_seconds', 'resetAfterSeconds')):
            signals[prefix + target] = window.get(snake, window.get(camel))
        seconds = window.get('limit_window_seconds', window.get('limitWindowSeconds'))
        if seconds is not None:
            try:
                signals[prefix + 'window-minutes'] = float(seconds) / 60
            except (ValueError, TypeError):
                pass
    summary = quota_summary(signals, observed_at)
    if not summary['quota'] and not summary['reset_times']:
        raise ValueError('quota response has no windows')
    plan = payload.get('plan_type', payload.get('planType'))
    if isinstance(plan, str) and plan.strip():
        summary['plan_type'] = plan
    return summary


class QuotaCache:
    """Fetch only visible credentials, deduplicating pending calls and caching safe fields."""
    def __init__(self, fetch, log=lambda *_args: None, clock=time.monotonic):
        self.fetch, self.log, self.clock = fetch, log, clock
        self.lock = threading.Lock()
        self.entries = {}
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='quota')

    def get(self, credential):
        auth_index = credential.get('auth_index') or credential.get('authIndex')
        if not auth_index:
            return {}
        key = (str(auth_index), str(credential.get('name') or ''), str(credential.get('updated_at') or credential.get('modtime') or ''), str(credential.get('last_refresh') or ''))
        with self.lock:
            now = self.clock()
            entry = self.entries.setdefault(key, {'data': {}, 'expires': 0, 'future': None, 'error': None})
            future = entry['future']
            if future is not None and future.done():
                data, error = future.result()
                if data:
                    entry['data'] = data
                entry.update(error=error, expires=now + (QUOTA_ERROR_CACHE_SECONDS if error else QUOTA_CACHE_SECONDS), future=None)
            if entry['future'] is None and now >= entry['expires']:
                entry['future'] = self.executor.submit(self._fetch, dict(credential))
            # Bound old identities when credentials are repeatedly replaced.
            if len(self.entries) > 1000:
                for old_key, old in list(self.entries.items()):
                    if old_key != key and old['future'] is None and old['expires'] <= now:
                        self.entries.pop(old_key)
            return {**entry['data'], 'quota_loading': entry['future'] is not None, 'quota_error': entry['error']}

    def _fetch(self, credential):
        try:
            payload = self.fetch(credential)
            data = usage_summary(payload, datetime.now(timezone.utc).isoformat())
            return data, None
        except Exception as exc:
            status = getattr(exc, 'status', 0)
            error = f'额度查询失败（HTTP {status}）' if status else '额度查询失败，请查看 CPA 连接或额度响应'
            self.log(f"[{credential.get('email') or credential.get('name') or 'Codex'}] {error}；保留历史观测，稍后重试", 'error')
            return {}, error

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)


def account_summary(serial, email, files, status):
    matches = matching_credentials(email, files)
    credential = selected_credential(email, files)
    claims = credential.get('id_token')
    claims = claims if isinstance(claims, dict) else {}
    snapshots = [credential.get('quota') or {}] + list((credential.get('model_quotas') or {}).values())
    snapshot = max((entry for entry in snapshots if isinstance(entry, dict) and entry.get('signals')), key=lambda item: as_timestamp(item.get('observed_at')) or '', default={})
    signals = {str(key).lower(): value for key, value in (snapshot.get('signals') or {}).items()}
    plan = claims.get('plan_type') or claims.get('chatgpt_plan_type') or signals.get('x-codex-plan-type') or credential.get('plan_type')
    quota = quota_summary(signals, as_timestamp(snapshot.get('observed_at')))
    return {'serial': serial, 'email': email, 'status': status, 'plan_type': plan, **quota,
            'last_refresh': as_timestamp(credential.get('last_refresh')), 'credential_count': len(matches),
            'credential_name': str(credential.get('name') or ''), 'success': credential.get('success', 0), 'failed': credential.get('failed', 0)}


class RuntimeState:
    """Store only preferences and blocked account states, never passwords or tokens."""
    def __init__(self, path, auto_reauth=False):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.auto_reauth = auto_reauth
        self.accounts = {}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding='utf-8'))
            self.auto_reauth = data.get('auto_reauth', auto_reauth) is True
            self.accounts = {email: status for email, status in data.get('accounts', {}).items() if status in {'deleted', 'error', 'paused'}}

    def save(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps({'auto_reauth': self.auto_reauth, 'accounts': self.accounts}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            os.chmod(temporary, 0o600)
            temporary.replace(self.path)

    def set_enabled(self, enabled):
        with self.lock:
            previous = self.auto_reauth
            self.auto_reauth = enabled
            try:
                self.save()
            except OSError:
                self.auto_reauth = previous
                raise

    def account_result(self, email, status):
        with self.lock:
            if status in {'deleted', 'error', 'paused'}:
                self.accounts[email] = status
            else:
                self.accounts.pop(email, None)
            self.save()
