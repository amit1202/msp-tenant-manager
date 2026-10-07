#!/usr/bin/env python3
"""Octopus MC live status dashboard.

Standard library only. Pulls live numbers from the Management Console API with
OAuth 2.0 client credentials (Security -> Clients in the MC), the same API the
MC MCP server uses, and serves a management dashboard that refreshes itself.

    python3 server.py                     # serve http://127.0.0.1:8088 (last 30 days, refreshed every minute)
    python3 server.py --check             # verify credentials + connectivity
    python3 server.py --snapshot out.html # write a self-contained HTML snapshot
    python3 server.py --demo data.json    # serve a saved stats JSON (no MC calls)

Configuration: ~/.config/mc-dashboard/config.json (or $MC_DASHBOARD_CONFIG),
overridable with MC_HOST / MC_CLIENT_ID / MC_CLIENT_SECRET env vars.
"""
import argparse
import base64
import datetime as dt
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'dashboard.html'
DEFAULT_CONFIG = Path.home() / '.config' / 'mc-dashboard' / 'config.json'
USER_AGENT = 'mc-live-dashboard/1.0'

DEFAULTS = {
    'host': 'secret.doubleoctopus.io',
    'environmentName': 'Octopus Production',
    'clientId': '',
    'clientSecret': '',
    'resource': 'mc-api',
    'tokenAuthMethod': 'client_secret_post',  # or client_secret_basic
    'bind': '127.0.0.1',
    'port': 8088,
    'refreshSeconds': 300,     # 5 minutes keeps the load on the MC low; minimum 60
    'windowDays': 30,          # rolling window; set windowHours instead for a window shorter than a day
    'timezone': 'Asia/Jerusalem',  # day boundaries for the daily chart
    'overlapMinutes': 10,      # each incremental fetch re-reads this much history to catch late-indexed events
    'auditPageSize': 100,      # the MC audit API accepts 1-100 rows per page
    'timeoutSeconds': 30,
    'viewKey': '',  # optional shared key: viewers open /?key=<viewKey>
    # Services whose "Octopus authentication" events are workstation logons (already counted from the
    # desktop agents). Empty = auto: ADPA services named "Active Directory...".
    'workstationServices': [],
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path=None):
    cfg = dict(DEFAULTS)
    path = Path(path or os.environ.get('MC_DASHBOARD_CONFIG') or DEFAULT_CONFIG)
    if path.exists():
        cfg.update(json.loads(path.read_text()))
    for key, env in (('host', 'MC_HOST'), ('clientId', 'MC_CLIENT_ID'), ('clientSecret', 'MC_CLIENT_SECRET')):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    cfg['host'] = re.sub(r'^https?://', '', cfg['host']).strip('/')
    cfg['windowHours'] = int(cfg.get('windowHours') or cfg['windowDays'] * 24)
    cfg['_path'] = str(path)
    return cfg


# ---------------------------------------------------------------------------
# MC API client
# ---------------------------------------------------------------------------

class McError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))


class McClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = f"https://{cfg['host']}"
        self._token = None
        self._renew_at = 0
        self._lock = threading.Lock()

    def _http(self, method, url, headers=None, data=None):
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={'User-Agent': USER_AGENT, 'Accept': 'application/json', **(headers or {})})
        try:
            try:
                resp = _opener.open(req, timeout=self.cfg['timeoutSeconds'])
            except urllib.error.HTTPError as err:
                resp = err
            with resp:
                return resp.status, resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise McError(f'Connection to {self.cfg["host"]} failed: {getattr(err, "reason", err)}') from None

    def token(self, force=False):
        with self._lock:
            if self._token and not force and time.monotonic() < self._renew_at:
                return self._token
            if not self.cfg['clientId'] or not self.cfg['clientSecret']:
                raise McError(f'clientId / clientSecret missing - set them in {self.cfg["_path"]}')
            form = {'grant_type': 'client_credentials', 'resource': self.cfg['resource']}
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            if self.cfg['tokenAuthMethod'] == 'client_secret_basic':
                creds = ':'.join(urllib.parse.quote_plus(v, safe='') for v in (self.cfg['clientId'], self.cfg['clientSecret']))
                headers['Authorization'] = 'Basic ' + base64.b64encode(creds.encode()).decode()
            else:
                form.update(client_id=self.cfg['clientId'], client_secret=self.cfg['clientSecret'])
            status, raw = self._http('POST', f'{self.base}/oauth/token', headers, urllib.parse.urlencode(form).encode())
            try:
                body = json.loads(raw or b'{}')
            except ValueError:
                body = {}
            if status != 200 or 'access_token' not in body:
                raise McError(f'Token request failed (HTTP {status}): {body.get("error_description") or body.get("error") or raw[:200]!r}')
            life = int(body.get('expires_in', 900))
            self._token = body['access_token']
            self._renew_at = time.monotonic() + life - min(60, life * 0.1)
            return self._token

    def get(self, path, query=None):
        url = f'{self.base}/admin/api{path}'
        if query:
            url += '?' + urllib.parse.urlencode(query)
        for attempt in (0, 1):
            status, raw = self._http('GET', url, {'Authorization': f'Bearer {self.token(force=attempt == 1)}'})
            if status == 401 and attempt == 0:
                continue
            break
        if status != 200:
            raise McError(f'GET {path} -> HTTP {status}: {raw[:200]!r}')
        return json.loads(raw)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def iso(ts):
    return ts.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{ts.microsecond // 1000:03d}Z'


def parse_ts(value):
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(dt.timezone.utc)
    except (AttributeError, ValueError):
        return None


# Only the audit events the dashboard needs, as separate server-side searches. This keeps a 30-day window
# small: the bulk of the audit log is Kerberos renewals and mobile/push chatter.
AUDIT_STREAMS = {
    'app': {'search': 'action:Octopus authentication'},
    'mac': {'filter': 'source:Mac Workstation', 'search': 'message:succeeded'},
    'win': {'filter': 'source:Windows Workstation', 'search': 'message:User operation succeeded'},
    'error': {'filter': 'level:error'},
    # Session evidence for which authenticator was used (every source shares the sign-in's sessionId)
    'push': {'filter': 'source:Authentication Server', 'search': 'message:User selected'},
    'bio': {'filter': 'source:Octopus Mobile App', 'search': 'message:Biometric verification succeeded'},
    'ble': {'search': 'action:BLE'},
    # FIDO2 / passkey sign-ins never produce an "Octopus authentication" event - they are FIDO Server
    # "FIDO2 assertion" events, and the app they unlock is the SAML login in the same session.
    'fido': {'filter': 'source:FIDO Server'},
    'saml': {'filter': 'source:Authentication Server', 'search': 'action:SAML login'},
    # Names the machine of a server-side workstation logon, for agents that don't upload their own events
    'wsupd': {'filter': 'source:Management Console', 'search': 'action:Update Workstation'},
}
ES_WINDOW = 9500  # Elasticsearch refuses page * size beyond 10,000 - split the time range instead
MAX_AUDIT_PAGE = 100  # /audit/es rejects size > 100 (HTTP 400 "size must be between 1 and 100")


def audit_page(client, query, start, end, page, size):
    return client.get('/audit/es', {**query, 'page': page, 'size': size, 'sort': 'timestamp:desc',
                                    'time': f'{iso(start)},{iso(end)}'})


def fetch_range(client, query, start, end, size):
    """All rows of one stream in [start, end]."""
    first = audit_page(client, query, start, end, 1, size)
    total = int(first.get('totalLogs') or 0)
    if total > ES_WINDOW and end - start > dt.timedelta(minutes=2):
        mid = start + (end - start) / 2
        return fetch_range(client, query, mid, end, size) + fetch_range(client, query, start, mid, size)
    rows, page = list(first.get('logs') or []), 1
    while len(rows) < total and page < int(first.get('total') or 0):
        page += 1
        batch = audit_page(client, query, start, end, page, size).get('logs') or []
        if not batch:
            break
        rows.extend(batch)
    return rows


def count_logs(client, query, start, end):
    return int(audit_page(client, query, start, end, 1, 1).get('totalLogs') or 0)


def row_key(row):
    return row.get('id') or (row.get('timestamp'), row.get('action'), row.get('user'), row.get('message'), row.get('deviceName'))


class AuditStore:
    """Keeps the rolling window of audit rows in memory: one full load, then only new events each refresh."""

    def __init__(self, client, cfg):
        self.client, self.cfg = client, cfg
        self.rows = {name: {} for name in AUDIT_STREAMS}
        self.covered_until = None
        self.lock = threading.Lock()

    def refresh(self, now):
        start = now - dt.timedelta(hours=self.cfg['windowHours'])
        since = start if self.covered_until is None else max(
            start, self.covered_until - dt.timedelta(minutes=self.cfg['overlapMinutes']))
        size = max(1, min(int(self.cfg['auditPageSize']), MAX_AUDIT_PAGE))
        fetched = {name: fetch_range(self.client, q, since, now, size)
                   for name, q in AUDIT_STREAMS.items()}
        with self.lock:
            for name, batch in fetched.items():
                bucket = self.rows[name]
                for row in batch:
                    bucket[row_key(row)] = row
                for k in [k for k, r in bucket.items() if (parse_ts(r.get('timestamp')) or now) < start]:
                    del bucket[k]
            self.covered_until = now
            return sum(len(b) for b in fetched.values())

    def snapshot(self):
        with self.lock:  # one row can match several streams - return it once
            return list({k: r for bucket in self.rows.values() for k, r in bucket.items()}.values())


def fetch_workstations(client):
    rows, page = [], 0
    while True:
        data = client.get('/workstations', {'pageNum': page, 'pageSize': 100})
        batch = data.get('results') or data.get('data') or []
        rows.extend(batch)
        if not batch or len(rows) >= int(data.get('total') or 0):
            return rows
        page += 1


def collect(client, cfg, store):
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=cfg['windowHours'])
    errors = []

    def safe(name, fn, default=None):
        try:
            return fn()
        except McError as err:
            errors.append(f'{name}: {err}')
            return default

    status = safe('system status', lambda: client.get('/settings/status'), {})
    directories = safe('directories', lambda: client.get('/directories', {'pageSize': 100}), {}) or {}
    dir_rows = directories.get('data') or directories.get('results') or []
    dir_stats = []
    for d in dir_rows:
        m = safe(f'directory {d.get("name")}', lambda d=d: client.get(f'/directories/{d["id"]}/members',
                                                                      {'pageSize': 1, 'path': ''}), {}) or {}
        dir_stats.append({'id': d.get('id'), 'name': d.get('name'), 'type': d.get('type'), 'lastSync': d.get('lastSync'),
                          **{k: m.get(k, 0) for k in ('userCount', 'activeCount', 'pendingCount', 'inactiveCount',
                                                      'blockedCount', 'bypassCount')}})
    services = safe('services', lambda: client.get('/services', {'pageSize': 200}), {}) or {}
    workstations = safe('workstations', lambda: fetch_workstations(client), []) or []
    new_rows = safe('audit log', lambda: store.refresh(now), 0)
    counts = {
        'failedEvents': safe('failed events', lambda: count_logs(client, {'filter': 'result:Failed'}, start, now)),
        'warnCount': safe('warnings', lambda: count_logs(client, {'filter': 'level:warn'}, start, now)),
    }
    store.context = {'now': now, 'start': start, 'status': status, 'dir_stats': dir_stats, 'services': services,
                     'workstations': workstations, 'errors': errors}
    stats = build_stats(cfg, now, start, status, dir_stats, services, workstations, store.snapshot(), errors, counts)
    stats['newAuditRows'] = new_rows
    return stats


def dir_name(dir_stats, path):
    m = re.match(r'root#(\d+)', path or '')
    names = {str(d['id']): d['name'] for d in dir_stats}
    return names.get(m.group(1), path) if m else path


def account_names(m):
    """Lower-case aliases an MC account can appear under in the audit log: username and email local parts."""
    return {n for n in ((m.get('username') or '').split('@')[0].lower(), (m.get('email') or '').split('@')[0].lower()) if n}


def resolve_person(client, key, dir_stats, max_lookups=6):
    """All MC accounts of the person behind `key`, and every name their events can be logged under.

    One person often has several accounts (e.g. "Amitl" in one directory, "amit.lavi" in another, an Entra ID
    UPN in a third) that share an email. Follow usernames and emails until no new alias turns up.
    """
    aliases, emails, accounts, queue, done = {key}, set(), {}, [key], set()
    while queue and len(done) < max_lookups:
        term = queue.pop(0)
        if term in done:
            continue
        done.add(term)
        for m in search_users(client, term, 25):
            names, email = account_names(m), (m.get('email') or '').lower()
            if not (names & aliases or (email and email in emails)):
                continue
            accounts[m.get('id') or (m.get('username'), m.get('path'))] = m
            if email:
                emails.add(email)
            for n in names - aliases:
                aliases.add(n)
                queue.append(n)
    rows = [{'displayName': m.get('displayName'), 'username': m.get('username'), 'email': m.get('email'),
             'status': m.get('status'), 'enabled': m.get('enabled'), 'bypass': m.get('bypass'),
             'activityAt': m.get('activityAt'), 'directory': dir_name(dir_stats, m.get('path'))}
            for m in accounts.values()]
    rows.sort(key=lambda r: (r['status'] != 'ACTIVE', r['directory'] or ''))
    return rows, aliases


def search_users(client, q, limit=10):
    data = client.get('/directories/explorer/members/search', {'search': q, 'filter': 'USERS', 'pageSize': limit,
                                                                'path': base64.urlsafe_b64encode(b'root').decode().rstrip('=')})
    return [m for m in data.get('data') or []]


def workstation_services(cfg, services):
    if cfg.get('workstationServices'):
        return {n.lower() for n in cfg['workstationServices']}
    rows = services.get('data') or services.get('results') or []
    return {r['name'].lower() for r in rows
            if r.get('type') == 'ADPA' and (r.get('name') or '').lower().startswith('active directory')}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

APP_MSG = re.compile(r'^(?:(Authentication (succeeded|failed))|(Adaptive Authentication)) for (.+?)(?: \(\d+\))?\s*$', re.I)
WS_SOURCES = {'Mac Workstation': 'macOS', 'Windows Workstation': 'Windows'}
WS_ACTIONS = {'unlock', 'logon', 'login'}


def os_family(name):
    n = (name or '').lower()
    if 'mac' in n or 'darwin' in n:
        return 'macOS'
    if 'windows' in n:
        return 'Windows'
    if 'linux' in n or 'ubuntu' in n:
        return 'Linux'
    return 'Other'


def user_key(raw):
    raw = (raw or '').strip()
    if not raw or raw.lower() in ('system', 'auth. server') or raw.startswith('api-client:'):
        return None
    return raw.split('@')[0].lower()


def classify(log, ws_services=frozenset()):
    """Return (kind, outcome, detail) for authentication events, else None.

    kind is 'app', 'workstation' (desktop-agent logon/unlock) or 'ws_server' (the auth-server side of a
    workstation logon - not counted again, only used for user activity).
    """
    action = log.get('action') or ''
    msg = (log.get('message') or '').strip()
    failed = (log.get('result') or '').lower() in ('failed', 'error')
    if log.get('source') == 'FIDO Server' and action == 'FIDO2 assertion':
        # "User authenticated" is the sign-in; "Logged in from FIDO Server" repeats it for portal logins
        if failed:
            return 'app', 'failed', FIDO_SERVICE
        if msg == 'User authenticated':
            return 'app', 'succeeded', FIDO_SERVICE
        return None
    if action == 'Octopus authentication':
        m = APP_MSG.match(msg)
        service = m.group(4) if m else (msg.split(' for ', 1)[-1] if ' for ' in msg else 'Unknown')
        if failed or (m and (m.group(2) or '').lower() == 'failed'):
            outcome = 'failed'
        elif m and m.group(3):
            outcome = 'adaptive'
        else:
            outcome = 'succeeded'
        service = re.sub(r' \(\d+\)$', '', service)
        return ('ws_server' if service.lower() in ws_services else 'app'), outcome, service
    platform = WS_SOURCES.get(log.get('source'))
    if platform and action.lower() in WS_ACTIONS:
        low = msg.lower()
        if 'succeeded' in low:
            return 'workstation', 'succeeded', platform
        if failed or 'failed' in low:
            return 'workstation', 'failed', platform
    return None


FIDO_SERVICE = '\0fido'  # placeholder; the real app comes from the session (see session_evidence)
SAML_LOGIN = re.compile(r'^(?:SAML|WS-Fed|OIDC) login \((\d+)\)', re.I)
AUTHENTICATORS = {  # label -> sort order in the UI
    'Passkey (FIDO2)': 0, 'Octopus push + biometrics': 1, 'Octopus push': 2, 'Octopus offline (BLE)': 3,
    'Trusted device (adaptive)': 4, 'Not recorded': 9,
}


def session_id(log):
    return (log.get('sessionId') or '').strip().lower()


EVIDENCE_WINDOW = (dt.timedelta(seconds=-30), dt.timedelta(seconds=5))  # around a sign-in without a sessionId


def session_evidence(logs):
    """Authenticator evidence: ({sessionId: {'signals', 'service_id'}}, {user: [(ts, signal)]}).

    Some services (LDAP, RADIUS) log without a sessionId; for those the evidence is matched by user and time.
    """
    sessions = defaultdict(lambda: {'signals': set(), 'service_id': None})
    by_user = defaultdict(list)
    for log in logs:
        sid = session_id(log)
        action, msg, source = log.get('action') or '', log.get('message') or '', log.get('source')
        if not sid:
            signal = ('push' if action == 'Mobile Server' and msg.startswith('User selected') else
                      'biometric' if action == 'Biometrics' and 'succeeded' in msg.lower() else
                      'ble' if 'ble' in action.lower() else None)
            key, ts = user_key(log.get('user')), parse_ts(log.get('timestamp'))
            if signal and key and ts:
                by_user[key].append((ts, signal))
            continue
        sess = sessions[sid]
        if source == 'FIDO Server' and action == 'FIDO2 assertion':
            sess['signals'].add('fido')
            if msg == 'Logged in from FIDO Server':
                sess['signals'].add('portal')
        elif action == 'Mobile Server' and msg.startswith('User selected'):
            sess['signals'].add('push')
        elif source == 'Octopus Mobile App' and action == 'Biometrics' and 'succeeded' in msg.lower():
            sess['signals'].add('biometric')
        elif 'ble' in action.lower():
            sess['signals'].add('ble')
        elif source in WS_SOURCES:
            if action.lower() in WS_ACTIONS and 'succeeded' in msg.lower():
                sess['signals'].add('agent')  # the desktop agent reported this logon itself
        elif action == 'Update Workstation':
            name = workstation_name_from_update(msg)
            if name:
                sess['device'] = name
        else:
            m = SAML_LOGIN.match(action)
            if m:
                sess['service_id'] = m.group(1)
    return sessions, by_user


def workstation_name_from_update(msg):
    """'Workstation (id=<hardware id>_<base64 name>) was created/updated' -> machine name."""
    m = re.search(r'id=[^)]*_([A-Za-z0-9+/=_-]+)\)', msg or '')
    if not m:
        return None
    raw = m.group(1)
    try:
        return base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_' if ('-' in raw or '_' in raw) else None).decode('utf-8').strip() or None
    except (ValueError, UnicodeDecodeError):
        return None


def nearby_signals(by_user, key, ts):
    lo, hi = EVIDENCE_WINDOW
    return {sig for t, sig in by_user.get(key, ()) if ts + lo <= t <= ts + hi}


def authenticator_for(outcome, signals, kind=None, has_session=False):
    if 'fido' in signals:
        return 'Passkey (FIDO2)'
    if outcome == 'adaptive':
        return 'Trusted device (adaptive)'
    if 'ble' in signals:
        return 'Octopus offline (BLE)'
    if 'push' in signals:
        return 'Octopus push + biometrics' if 'biometric' in signals else 'Octopus push'
    if kind == 'workstation' and has_session:
        # The workstation's session reached the server and was accepted without any prompt: the AD
        # services allow adaptive (trusted device) authentication.
        return 'Trusted device (adaptive)'
    return 'Not recorded'


def make_buckets(cfg, start, now):
    """Daily buckets (local midnight) for windows over 2 days, hourly otherwise. Returns (unit, buckets, index_fn)."""
    tz = ZoneInfo(cfg['timezone'])
    if cfg['windowHours'] > 48:
        day0 = start.astimezone(tz).date()
        days = (now.astimezone(tz).date() - day0).days + 1
        buckets = [{'start': iso(dt.datetime.combine(day0 + dt.timedelta(days=i), dt.time(), tz)), 'app': 0,
                    'Windows': 0, 'macOS': 0} for i in range(days)]
        return 'day', buckets, lambda ts: (ts.astimezone(tz).date() - day0).days
    hours = cfg['windowHours']
    buckets = [{'start': iso(start + dt.timedelta(hours=h)), 'app': 0, 'Windows': 0, 'macOS': 0} for h in range(hours)]
    return 'hour', buckets, lambda ts: min(int((ts - start).total_seconds() // 3600), hours - 1)


def dev_key(name):
    """Workstation identity across sources: 'refael-lap.doubleoctopus.com' and 'REFAEL-LAP' are the same machine."""
    return (name or '').strip().lower().split('.')[0]


def build_stats(cfg, now, start, status, dir_stats, services, workstations, logs, errors, counts=None,
                include=None):
    """Aggregate the window. `include(kind, detail, log)` limits the sign-ins counted (user/app/device views);
    session evidence is always read from all `logs` so the authenticator is still found."""
    counts = counts or {}
    hours = cfg['windowHours']
    unit, buckets, bucket_of = make_buckets(cfg, start, now)
    tz = ZoneInfo(cfg['timezone'])
    today0 = dt.datetime.combine(now.astimezone(tz).date(), dt.time(), tz)
    cutoff24 = now - dt.timedelta(hours=24)
    period = Counter()
    feed = []
    devices = {}
    active_days = set()
    by_service = defaultdict(lambda: {'succeeded': 0, 'adaptive': 0, 'failed': 0})
    users = defaultdict(lambda: {'app': 0, 'workstation': 0, 'names': Counter(), 'last': None})
    active_devices = {'Windows': set(), 'macOS': set()}
    ws_counts = {'Windows': {'succeeded': 0, 'failed': 0}, 'macOS': {'succeeded': 0, 'failed': 0}}
    app_counts = Counter()
    last15 = 0
    level_counts = Counter()
    failed_events = 0
    ws_server_failed = 0
    error_rows = []
    cutoff15 = now - dt.timedelta(minutes=15)
    ws_services = workstation_services(cfg, services)
    evidence, evidence_by_user = session_evidence(logs)
    service_names = {str(r.get('id')): r.get('name') for r in (services.get('data') or services.get('results') or [])}
    by_auth = Counter()
    by_service_auth = defaultdict(Counter)
    registry = {dev_key(w.get('name')): w for w in workstations}

    for log in logs:
        level = (log.get('level') or '').lower()
        if include is None:
            level_counts[level] += 1
            if (log.get('result') or '').lower() == 'failed':
                failed_events += 1
            if level == 'error':
                error_rows.append({k: log.get(k) for k in ('timestamp', 'source', 'action', 'message', 'user')})
        hit = classify(log, ws_services)
        if not hit:
            continue
        kind, outcome, detail = hit
        ts = parse_ts(log.get('timestamp'))
        ev = evidence.get(session_id(log))
        if kind == 'ws_server' and ev and ev.get('device') and 'agent' not in ev['signals']:
            # Workstation logon whose agent never sent its own events (seen on some Windows agents):
            # count the server side, on the machine named in the session's "Update Workstation" event.
            reg = registry.get(dev_key(ev['device'])) or {}
            family = os_family(reg.get('osName')) if reg else 'Windows'
            if family in ('Windows', 'macOS'):
                kind, detail = 'workstation', family
                log = {**log, 'deviceName': reg.get('name') or ev['device'], 'source': f'{family} (server-side)'}
                ws_server_failed += outcome == 'failed'
            else:  # e.g. the AI gateway server: a sign-in to the service, not a workstation logon
                kind = 'app'
        if detail == FIDO_SERVICE:
            sid = ev and ev['service_id']
            detail = service_names.get(sid) or (f'Service {sid}' if sid else 'Portal' if ev and 'portal' in ev['signals']
                                                 else 'Portal')
        signals = set(ev['signals']) if ev else set()
        if not signals - {'portal'} and ts:
            signals |= nearby_signals(evidence_by_user, user_key(log.get('user')), ts)
        method = authenticator_for(outcome, signals, kind, has_session=ev is not None)
        if include is not None and not include(kind, detail, log):
            continue
        if kind != 'ws_server' and outcome != 'failed':
            by_auth[method] += 1
            if kind == 'app':
                by_service_auth[detail][method] += 1
        if kind == 'app':
            by_service[detail][outcome] += 1
            app_counts[outcome] += 1
        elif kind == 'workstation':
            ws_counts[detail][outcome] += 1
        else:
            ws_server_failed += outcome == 'failed'
        if kind != 'ws_server' and ts:
            feed.append((ts, {'timestamp': iso(ts), 'user': (log.get('user') or '').split('@')[0].lower(),
                              'kind': kind, 'detail': detail, 'outcome': outcome, 'authenticator': method}))
        if outcome == 'failed':
            continue
        key = user_key(log.get('user'))
        if key:
            u = users[key]
            if ts and (u['last'] is None or ts > u['last']):
                u['last'] = ts
            if kind != 'ws_server':
                u[kind] += 1
                u['names'][(log.get('user') or '').split('@')[0]] += 1
        if kind == 'ws_server':
            continue
        if ts and ts >= cutoff15:
            last15 += 1
        if ts and ts >= cutoff24:
            period['last24h'] += 1
        if ts and ts >= today0:
            period['today'] += 1
        if ts and start <= ts <= now:
            idx = bucket_of(ts)
            if 0 <= idx < len(buckets):
                buckets[idx]['app' if kind == 'app' else detail] += 1
        if ts:
            active_days.add(ts.astimezone(tz).date())
        if kind == 'workstation' and log.get('deviceName'):
            active_devices[detail].add(log['deviceName'].lower())
            dev = devices.setdefault(log['deviceName'].lower(), {'name': log['deviceName'], 'os': detail, 'count': 0, 'last': ts})
            dev['count'] += 1
            if ts and (dev['last'] is None or ts > dev['last']):
                dev['last'] = ts

    ranked = sorted(((k, v) for k, v in users.items() if v['app'] + v['workstation']), key=lambda kv: (-(kv[1]['app'] + kv[1]['workstation']), -kv[1]['app'], kv[0]))
    top_users = [{'user': k, 'display': v['names'].most_common(1)[0][0].lower() if v['names'] else k,
                  'app': v['app'], 'workstation': v['workstation'], 'total': v['app'] + v['workstation'],
                  'lastSeen': iso(v['last']) if v['last'] else None} for k, v in ranked[:5]]

    ws_os = Counter(os_family(w.get('osName')) for w in workstations)
    total_users = {k: sum(d.get(k) or 0 for d in dir_stats)
                   for k in ('userCount', 'activeCount', 'pendingCount', 'inactiveCount', 'blockedCount', 'bypassCount')}

    components = []
    for key, label in (('servers', 'Authentication servers'), ('mobile', 'Mobile push service'), ('db', 'Database'),
                       ('directories', 'Directories'), ('replicas', 'Replicas'), ('agents', 'AD agents'),
                       ('authenticators', 'Authenticators'), ('audit', 'Audit server'), ('email', 'Email service'),
                       ('license', 'License')):
        item = status.get(key)
        if isinstance(item, dict):
            parts = item.get('data') if isinstance(item.get('data'), list) else []
            detail = []
            for p in parts:
                if isinstance(p, dict) and p.get('status') is False:
                    why = 'not installed' if p.get('installed') is False else (p.get('message') or 'unavailable')
                    detail.append(f"{p.get('name') or p.get('id')} ({why})")
            message = item.get('message') or ('Operational' if item.get('status') else 'Degraded')
            components.append({'name': label, 'ok': bool(item.get('status')), 'message': message,
                               'failing': detail})
    lic = (status.get('license') or {}).get('data') or {}
    version = ((status.get('version') or {}).get('data') or {}).get('version')

    app_total = sum(app_counts.values())
    ws_ok = sum(v['succeeded'] for v in ws_counts.values())
    return {
        'generatedAt': iso(now),
        'window': {'start': iso(start), 'end': iso(now), 'hours': hours, 'days': round(hours / 24, 1),
                   'bucket': unit, 'timezone': cfg['timezone']},
        'environment': {'name': cfg['environmentName'], 'host': cfg['host'], 'version': version},
        'refreshSeconds': cfg['refreshSeconds'],
        'users': {**total_users, 'directories': dir_stats, 'activeInWindow': len(users)},
        'license': {k: lic.get(k) for k in ('licenseType', 'pool', 'inUse', 'expirationDate', 'expired')},
        'authentications': {
            'total': app_total - app_counts['failed'] + ws_ok,
            'last15Minutes': last15,
            'last24Hours': period['last24h'],
            'today': period['today'],
            'recent': [row for _, row in sorted(feed, key=lambda x: x[0], reverse=True)[:15]],
            'applications': {'total': app_total, **{k: app_counts[k] for k in ('succeeded', 'adaptive', 'failed')}},
            'workstations': ws_counts,
            'workstationServices': sorted(ws_services),
            'byService': sorted(({'service': k, **v, 'total': sum(v.values()),
                                  'authenticators': dict(by_service_auth[k])} for k, v in by_service.items()),
                                key=lambda r: -r['total']),
            'byAuthenticator': [{'name': k, 'count': n} for k, n in
                                sorted(by_auth.items(), key=lambda kv: (AUTHENTICATORS.get(kv[0], 5), -kv[1]))],
            'series': buckets,
        },
        'workstations': {'registered': len(workstations), 'byOs': dict(ws_os),
                         'activeInWindow': {k: len(v) for k, v in active_devices.items()}},
        'services': {k: services.get(k) for k in ('total', 'enabledCount', 'disabledCount', 'validCount', 'inValidCount')},
        'topUsers': top_users,
        'devices': [{**d, 'last': iso(d['last']) if d['last'] else None}
                    for d in sorted(devices.values(), key=lambda d: -d['count'])[:10]],
        'activeDays': len(active_days),
        'errors': {'errorCount': level_counts['error'],
                   'warnCount': counts.get('warnCount', level_counts['warn']),
                   'failedEvents': counts.get('failedEvents', failed_events),
                   'failedAuthentications': app_counts['failed'] + ws_server_failed,
                   'recent': sorted(error_rows, key=lambda r: r.get('timestamp') or '', reverse=True)[:10]},
        'system': {'components': components, 'allOk': bool(components) and all(c['ok'] for c in components)},
        'auditRowsScanned': len(logs),
        'collectionErrors': errors,
    }


# ---------------------------------------------------------------------------
# Rendering + HTTP
# ---------------------------------------------------------------------------

def render(stats=None):
    html = TEMPLATE.read_text()
    if stats is None:
        return html
    blob = json.dumps(stats).replace('</', '<\\/')
    return html.replace('<!--SNAPSHOT-->', f'<script>window.__MC_SNAPSHOT__ = {blob};</script>')


SETTINGS_PAGE = HERE / 'settings.html'
EDITABLE = {  # field -> (type, min, max)
    'host': (str, None, None), 'environmentName': (str, None, None), 'clientId': (str, None, None),
    'clientSecret': (str, None, None), 'tokenAuthMethod': (str, None, None), 'timezone': (str, None, None),
    'windowDays': (int, 1, 90), 'refreshSeconds': (int, 60, 3600), 'viewKey': (str, None, None),
    'bind': (str, None, None), 'port': (int, 1, 65535),
}
RESTART_FIELDS = ('bind', 'port')


def validate(cfg, changes):
    """Merge editable fields from `changes` into a copy of cfg. Blank clientSecret keeps the saved one."""
    out, problems = dict(cfg), []
    for name, value in changes.items():
        if name not in EDITABLE:
            continue
        kind, lo, hi = EDITABLE[name]
        if name == 'clientSecret' and not value:
            continue
        try:
            value = kind(value).strip() if kind is str else kind(value)
        except (TypeError, ValueError):
            problems.append(f'{name} must be a number')
            continue
        if kind is int and not (lo <= value <= hi):
            problems.append(f'{name} must be between {lo} and {hi}')
            continue
        out[name] = value
    out['host'] = re.sub(r'^https?://', '', out['host']).strip('/')
    if not re.fullmatch(r'[A-Za-z0-9.-]+(:\d+)?', out['host'] or ''):
        problems.append('host must be a hostname such as secret.doubleoctopus.io')
    if out['tokenAuthMethod'] not in ('client_secret_post', 'client_secret_basic'):
        problems.append('tokenAuthMethod must be client_secret_post or client_secret_basic')
    try:
        ZoneInfo(out['timezone'])
    except Exception:
        problems.append(f'unknown timezone {out["timezone"]!r}')
    out['windowHours'] = out['windowDays'] * 24
    return out, problems


def save_config(cfg):
    path = Path(cfg['_path'])
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {k: cfg[k] for k in DEFAULTS if k in cfg and k != 'windowHours'}
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def public_config(cfg):
    out = {k: cfg.get(k) for k in EDITABLE if k != 'clientSecret'}
    out['clientSecretSet'] = bool(cfg.get('clientSecret'))
    out['configPath'] = cfg['_path']
    return out


def configured(cfg):
    return bool(cfg.get('host') and cfg.get('clientId') and cfg.get('clientSecret'))


class App:
    """Holds the live config, MC client and audit store; refreshes stats in the background."""

    def __init__(self, cfg, demo=None):
        self.cfg, self.demo = cfg, demo
        self.lock = threading.Lock()
        self.value, self.error = None, None
        self.wake = threading.Event()
        self.run_lock = threading.Lock()  # one refresh at a time (background loop or manual)
        self.last_run = 0
        self.profiles = {}
        self._build()

    def _build(self):
        self.client = McClient(self.cfg)
        self.store = AuditStore(self.client, self.cfg)
        self.generation = getattr(self, 'generation', 0) + 1

    def produce(self):
        if self.demo is not None:
            return self.demo
        if not configured(self.cfg):
            raise McError('not configured')
        return collect(self.client, self.cfg, self.store)

    def run_once(self):
        with self.run_lock:
            self._run()
            self.last_run = time.monotonic()

    def refresh_now(self, min_gap=30):
        """Manual refresh. Requests within `min_gap` seconds of the last refresh reuse its result."""
        if time.monotonic() - self.last_run >= min_gap:
            if self.run_lock.locked():  # a refresh is already running - wait for it rather than starting another
                with self.run_lock:
                    pass
            else:
                self.run_once()
        return self.get()

    def _run(self):
        gen = self.generation
        try:
            value, error = self.produce(), None
        except Exception as err:  # keep serving the last good data
            value, error = None, str(err)
            sys.stderr.write(f'refresh failed: {err}\n')
        with self.lock:
            if gen != self.generation:  # config changed mid-run; discard
                return
            if value is not None:
                self.value = value
            self.error = error

    def start(self):
        def loop():
            while True:
                started = time.monotonic()
                self.run_once()
                self.wake.wait(max(5, self.cfg['refreshSeconds'] - (time.monotonic() - started)))
                self.wake.clear()
        threading.Thread(target=loop, daemon=True, name='refresher').start()

    def get(self):
        with self.lock:
            if self.value is None:
                raise McError(self.error or 'warming up')
            return {**self.value, 'staleError': self.error} if self.error else self.value

    def user_view(self, key):
        """Stats for one user, from the rows already in memory (plus a cached MC profile lookup)."""
        key = (key or '').strip().split('@')[0].lower()
        base = self.get()
        ctx = self._context()
        cached = self.profiles.get(key)
        if not cached or time.monotonic() - cached[0] > 600:
            try:
                accounts, aliases = resolve_person(self.client, key, ctx['dir_stats'])
                cached = (time.monotonic(), accounts, aliases)
            except McError as err:  # still show activity under the typed name; retry the lookup in a minute
                cached = (time.monotonic() - 540, [{'error': str(err)}], {key})
            self.profiles[key] = cached
        _, accounts, aliases = cached
        stats = self._focused(ctx, lambda kind, detail, log: user_key(log.get('user')) in aliases)
        names = Counter(a.get('displayName') for a in accounts if a.get('displayName'))
        display = names.most_common(1)[0][0] if names else key
        stats['user'] = {'key': key, 'display': display, 'accounts': accounts, 'aliases': sorted(aliases)}
        return self._finish(stats, base, 'user', stats['user'])

    def _focused(self, ctx, include):
        return build_stats(self.cfg, ctx['now'], ctx['start'], ctx['status'], ctx['dir_stats'], ctx['services'],
                           ctx['workstations'], self.store.snapshot(), [], include=include)

    def _context(self):
        ctx = getattr(self.store, 'context', None)
        if self.demo is not None or ctx is None:
            raise McError('Filtered views need a live MC connection')
        return ctx

    def _finish(self, stats, base, scope, info):
        stats.update(scope=scope, focus=info, generatedAt=base['generatedAt'], newAuditRows=base.get('newAuditRows'))
        return {**stats, 'staleError': base.get('staleError')} if base.get('staleError') else stats

    def app_view(self, name):
        """Stats for one application (service)."""
        base, ctx = self.get(), self._context()
        want = (name or '').strip().lower()
        stats = self._focused(ctx, lambda kind, detail, log: kind == 'app' and detail.lower() == want)
        rows = ctx['services'].get('data') or ctx['services'].get('results') or []
        svc = next((r for r in rows if (r.get('name') or '').lower() == want), None)
        info = {'key': name, 'display': svc.get('name') if svc else name,
                'service': {k: svc.get(k) for k in ('id', 'name', 'protocol', 'type', 'enabled', 'valid', 'created_at')}
                if svc else None}
        return self._finish(stats, base, 'app', info)

    def device_view(self, name):
        """Stats for one workstation."""
        base, ctx = self.get(), self._context()
        want = dev_key(name)
        stats = self._focused(ctx, lambda kind, detail, log: kind == 'workstation' and dev_key(log.get('deviceName')) == want)
        regs = [{k: w.get(k) for k in ('name', 'osName', 'osVersion', 'appName', 'appVersion', 'manufacturer', 'model',
                                      'tpmVersion', 'tpmActivated', 'createdAt', 'updatedAt')}
                for w in ctx['workstations'] if dev_key(w.get('name')) == want]
        regs.sort(key=lambda w: w.get('updatedAt') or '', reverse=True)
        display = next((d['name'] for d in stats.get('devices', [])), regs[0]['name'] if regs else name).split('.')[0]
        return self._finish(stats, base, 'device', {'key': want, 'display': display, 'registrations': regs})

    def search(self, q, limit=8):
        """Mixed suggestions for the search box: users, applications and workstations."""
        q = (q or '').strip().lower()
        out = [{'type': 'user', **u} for u in self.user_list(q, limit)]
        apps, devices = Counter(), Counter()
        names = {}
        ctx = getattr(self.store, 'context', None)
        wss = workstation_services(self.cfg, ctx['services']) if ctx else set()
        for log in self.store.snapshot():
            hit = classify(log, wss)
            if not hit or hit[1] == 'failed':
                continue
            if hit[0] == 'workstation' and log.get('deviceName') and q in log['deviceName'].lower():
                k = dev_key(log['deviceName'])
                devices[k] += 1
                names.setdefault(k, log['deviceName'].split('.')[0])
        try:  # app counts from the main view, where passkey sign-ins are already resolved to their app
            for r in self.get()['authentications']['byService']:
                if q in r['service'].lower():
                    apps[r['service']] += r['total'] - r['failed']
        except McError:
            pass
        if ctx:  # services and machines with no sign-ins yet
            for r in ctx['services'].get('data') or []:
                n = r.get('name') or ''
                if q and q in n.lower() and n.lower() not in wss and n not in apps:
                    apps[n] += 0
            for w in ctx['workstations']:
                k = dev_key(w.get('name'))
                if q and k and q in k and k not in devices:
                    devices[k] += 0
                    names.setdefault(k, w.get('name'))
        out += [{'type': 'app', 'key': n, 'display': n, 'events': c} for n, c in apps.most_common(limit)]
        out += [{'type': 'device', 'key': k, 'display': names.get(k, k), 'events': c} for k, c in devices.most_common(limit)]
        return out

    def user_list(self, q, limit=10):
        """Users matching `q`: people with activity in the window first, then MC directory matches."""
        q = (q or '').strip().lower()
        counts, names = Counter(), {}
        for r in self.store.snapshot():
            k = user_key(r.get('user'))
            if k and (not q or q in k):
                counts[k] += 1
                names.setdefault(k, (r.get('user') or '').split('@')[0])
        out = [{'key': k, 'display': k, 'events': n} for k, n in counts.most_common(limit)]
        if len(out) < limit and len(q) >= 2 and self.demo is None and configured(self.cfg):
            seen = {u['key'] for u in out}
            try:
                for m in search_users(self.client, q, limit):
                    names = account_names(m)
                    hit = next((u for u in out if u['key'] in names), None)
                    if hit:  # another account of someone already listed - just put a real name on them
                        if hit['display'] == hit['key'] and m.get('displayName'):
                            hit['display'] = m['displayName']
                        seen |= names
                        continue
                    k = (m.get('username') or '').split('@')[0].lower() or next(iter(names), '')
                    if k and not names & seen:
                        seen |= names
                        out.append({'key': k, 'display': m.get('displayName') or k, 'events': 0,
                                    'status': m.get('status')})
            except McError:
                pass
        return out[:limit]

    def reconfigure(self, new_cfg):
        save_config(new_cfg)
        with self.lock:
            reset = any(new_cfg.get(k) != self.cfg.get(k) for k in
                        ('host', 'clientId', 'clientSecret', 'tokenAuthMethod', 'windowDays', 'timezone'))
            self.cfg.clear()
            self.cfg.update(new_cfg)
            if reset:
                self._build()
                self.value, self.error = None, None
            elif self.value is not None:
                self.value = {**self.value, 'refreshSeconds': self.cfg['refreshSeconds'],
                              'environment': {**self.value['environment'], 'name': self.cfg['environmentName']}}
        self.wake.set()


def test_connection(cfg):
    client = McClient(cfg)
    client.token(force=True)
    version = client.get('/settings/version')
    probes = {}
    for name, path, query in (('status', '/settings/status', None), ('directories', '/directories', {'pageSize': 1}),
                              ('services', '/services', {'pageSize': 1}), ('workstations', '/workstations', {'pageSize': 1}),
                              ('audit', '/audit/es', {'size': 1})):
        try:
            client.get(path, query)
            probes[name] = 'ok'
        except McError as err:
            probes[name] = str(err)
    return {'ok': all(v == 'ok' for v in probes.values()), 'version': version, 'access': probes}


def pick_view(app, query):
    for name, view in (('user', app.user_view), ('app', app.app_view), ('device', app.device_view)):
        value = (query.get(name) or [''])[0]
        if value:
            return view(value)
    return app.get()


def make_handler(app):
    def is_local(handler):
        return handler.client_address[0] in ('127.0.0.1', '::1', '::ffff:127.0.0.1')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write('[%s] %s\n' % (self.log_date_time_string(), fmt % args))

        def _send(self, code, body, ctype, extra=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            return self._send(code, json.dumps(obj), 'application/json')

        def _authorized(self, query):
            key = app.cfg.get('viewKey') or ''
            if not key:
                return True
            cookies = dict(c.strip().split('=', 1) for c in (self.headers.get('Cookie') or '').split(';') if '=' in c)
            return query.get('key', [''])[0] == key or cookies.get('mcdash') == key

        def do_GET(self):
            self._guard(self._get)

        def do_POST(self):
            self._guard(self._post)

        def _guard(self, fn):
            try:
                fn()
            except Exception as err:  # never drop the connection without an answer
                sys.stderr.write(f'error handling {self.command} {self.path}: {err!r}\n')
                try:
                    self._json(500, {'error': f'Internal error: {err}'})
                except OSError:
                    pass

        def _get(self):
            url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(url.query)
            if url.path == '/healthz':
                return self._send(200, 'ok', 'text/plain')
            if url.path in ('/settings', '/api/config'):
                if not is_local(self):
                    return self._send(403, 'Settings are only available on the machine running the dashboard.', 'text/plain')
                if url.path == '/settings':
                    return self._send(200, SETTINGS_PAGE.read_text(), 'text/html; charset=utf-8')
                return self._json(200, public_config(app.cfg))
            if not self._authorized(query):
                return self._send(403, 'Forbidden - open the dashboard link with its ?key=', 'text/plain')
            key = app.cfg.get('viewKey') or ''
            cookie = {'Set-Cookie': f'mcdash={key}; HttpOnly; SameSite=Strict; Path=/'} if key else None
            if url.path == '/':
                return self._send(200, render(), 'text/html; charset=utf-8', cookie)
            if url.path == '/api/users':
                return self._json(200, app.user_list((query.get('q') or [''])[0]))
            if url.path == '/api/search':
                return self._json(200, app.search((query.get('q') or [''])[0]))
            if url.path == '/api/stats':
                try:
                    return self._json(200, pick_view(app, query))
                except McError as err:
                    msg = str(err)
                    return self._json(503, {'error': msg, 'loading': msg == 'warming up',
                                            'needsConfig': msg == 'not configured', 'canConfigure': is_local(self)})
            if url.path == '/snapshot.html':
                try:
                    stats = pick_view(app, query)
                except McError as err:
                    return self._send(503, f'No data yet: {err}', 'text/plain')
                stamp = dt.datetime.now().strftime('%Y-%m-%d_%H%M')
                return self._send(200, render(stats), 'text/html; charset=utf-8',
                                  {'Content-Disposition': f'attachment; filename="octopus-status-{stamp}.html"'})
            self._send(404, 'Not found', 'text/plain')

        def _post(self):
            url = urllib.parse.urlparse(self.path)
            if url.path not in ('/api/config', '/api/config/test', '/api/refresh'):
                return self._send(404, 'Not found', 'text/plain')
            # JSON-only and same-origin, so a page on another site can't trigger these.
            origin = self.headers.get('Origin') or ''
            host = self.headers.get('Host') or ''
            if (origin and urllib.parse.urlparse(origin).netloc != host) \
                    or 'application/json' not in (self.headers.get('Content-Type') or ''):
                return self._send(403, 'Forbidden', 'text/plain')
            if url.path == '/api/refresh':
                if not self._authorized(urllib.parse.parse_qs(url.query)):
                    return self._send(403, 'Forbidden', 'text/plain')
                try:
                    app.refresh_now()
                    return self._json(200, pick_view(app, urllib.parse.parse_qs(url.query)))
                except McError as err:
                    return self._json(503, {'error': str(err)})
            if not is_local(self):  # configuration is local-only
                return self._send(403, 'Settings are only available on the machine running the dashboard.', 'text/plain')
            try:
                length = min(int(self.headers.get('Content-Length') or 0), 64 * 1024)
                changes = json.loads(self.rfile.read(length) or b'{}')
                assert isinstance(changes, dict)
            except (ValueError, AssertionError):
                return self._json(400, {'error': 'Body must be a JSON object'})
            new_cfg, problems = validate(app.cfg, changes)
            if problems:
                return self._json(400, {'error': '; '.join(problems)})
            if url.path == '/api/config/test':
                if not configured(new_cfg):
                    return self._json(400, {'error': 'Host, client ID and client secret are required'})
                try:
                    return self._json(200, test_connection(new_cfg))
                except McError as err:
                    return self._json(200, {'ok': False, 'error': str(err)})
            restart = [k for k in RESTART_FIELDS if new_cfg.get(k) != app.cfg.get(k)]
            app.reconfigure(new_cfg)
            return self._json(200, {'saved': True, 'restartNeeded': restart, 'config': public_config(app.cfg)})

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', help='config.json path')
    ap.add_argument('--port', type=int)
    ap.add_argument('--bind')
    ap.add_argument('--check', action='store_true', help='test credentials and exit')
    ap.add_argument('--snapshot', metavar='FILE', help='write a self-contained HTML snapshot and exit')
    ap.add_argument('--json', metavar='FILE', help='write the stats JSON and exit')
    ap.add_argument('--demo', metavar='FILE', help='serve a saved stats JSON instead of calling the MC')
    args = ap.parse_args()
    cfg = load_config(args.config)
    if args.port:
        cfg['port'] = args.port
    if args.bind:
        cfg['bind'] = args.bind
    app = App(cfg, demo=json.loads(Path(args.demo).read_text()) if args.demo else None)

    if args.check:
        result = test_connection(cfg)
        print(f'MC version {result["version"]} on {cfg["host"]}')
        for name, state in result['access'].items():
            print(f'  {name:13} {state}')
        sys.exit(0 if result['ok'] else 1)
    if args.snapshot or args.json:
        stats = app.produce()
        if args.json:
            Path(args.json).write_text(json.dumps(stats, indent=2))
        if args.snapshot:
            Path(args.snapshot).write_text(render(stats))
        print(f'Wrote {args.snapshot or args.json} ({stats["auditRowsScanned"]} audit rows, '
              f'{len(stats["collectionErrors"])} collection errors)')
        return

    app.start()  # first run loads the whole window; later runs fetch only new events
    server = ThreadingHTTPServer((cfg['bind'], cfg['port']), make_handler(app))
    suffix = f'/?key={cfg["viewKey"]}' if cfg.get('viewKey') else '/'
    print(f'Octopus live dashboard for {cfg["host"]} on http://{cfg["bind"]}:{cfg["port"]}{suffix} '
          f'(last {cfg["windowDays"]} days, refresh every {cfg["refreshSeconds"]}s)')
    if not configured(cfg):
        print(f'Not configured yet - open http://127.0.0.1:{cfg["port"]}/settings on this machine')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
