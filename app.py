import json
import os
import random
import time
import webbrowser
from datetime import date, timedelta
from flask import Flask, request, jsonify, render_template
import requests


class _TimeoutSession(requests.Session):
    """A requests.Session that applies a default timeout to every call unless the
    caller already specified one. simple_salesforce accepts a `session` kwarg but has
    no `timeout` option of its own, so every sf.query/create/update/query_all call
    normally has NO timeout at all — if Salesforce or the network ever stops
    responding mid-request without closing the socket, the call (and anything
    depending on it, e.g. the whole daily_sync.py run) hangs forever instead of
    raising. This surfaced as a launchd job stuck for 3+ days on a single dead
    connection, silently blocking every scheduled run behind it."""

    DEFAULT_TIMEOUT = 30

    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", self.DEFAULT_TIMEOUT)
        return super().request(*args, **kwargs)


def _request_with_retry(method, url, retries=3, base_timeout=15, **kwargs):
    """The MSP API occasionally takes 15-20s+ to respond (seen repeatedly in practice,
    including causing full daily-sync failures). Retry transient network errors with a
    growing timeout instead of failing outright on the first slow response."""
    last_exc = None
    for attempt in range(retries):
        try:
            return requests.request(method, url, timeout=base_timeout + attempt * 15, **kwargs)
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < retries - 1:
                time.sleep(2)
    raise last_exc

app = Flask(__name__)
app.secret_key = "msp-portal-secret-key"

DEFAULT_MSP_URL = "https://msp.doubleoctopus.io/mt"

def _msp_url():
    return load_creds().get("msp_url", "").strip().rstrip("/") or DEFAULT_MSP_URL
ALL_STATUSES = "INIT,INIT_DOMAIN_ALLOCATION,INIT_MC_SETUP,LIVE,ERROR,ERROR_SUBDOMAIN_REGISTRATION,SUSPENDED,MIGRATING,ERROR_SUBDOMAIN_RESTORE,DNS_UPDATING"
CREDS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")


# ── Credential helpers ────────────────────────────────────────────────────────

def load_creds():
    if os.path.exists(CREDS_FILE):
        with open(CREDS_FILE) as f:
            return json.load(f)
    return {}

def save_creds(data):
    existing = load_creds()
    # Never overwrite a saved sensitive field with an empty value
    for key in ("sf_password", "sf_token", "sf_session_id"):
        if key in data and not str(data[key]).strip():
            data.pop(key)
    existing.update(data)
    with open(CREDS_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# ── MSP helpers ───────────────────────────────────────────────────────────────

def _get_msp_name(t):
    msp = t.get("msp") or t.get("mspDetails") or t.get("reseller") or t.get("parent")
    if msp:
        if isinstance(msp, str): return msp
        if isinstance(msp, dict):
            return msp.get("name") or msp.get("companyName") or msp.get("id") or "Unknown MSP"
    return t.get("mspName") or t.get("msp_name") or "Unknown MSP"

def _get_tenant_name(t):
    for k in ("orgName", "name", "tenantName", "companyName", "displayName"):
        if t.get(k): return t[k]
    return t.get("subdomain") or t.get("id", "")

def _soql_escape(s):
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


SAML_LOGIN_URL = "https://secret.doubleoctopus.io/saml/fed554e1-3551-421a-bc05-21adbbd1dabd/login"
APP_PORT       = 5070


# ── Routes: credentials ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/creds/load", methods=["GET"])
def creds_load():
    c = load_creds()
    # Never return sensitive values to the browser
    safe = {k: v for k, v in c.items() if k not in ("sf_password", "sf_token", "sf_session_id")}
    safe["sf_session_id_saved"] = bool(c.get("sf_session_id"))
    safe["sf_password_saved"]   = bool(c.get("sf_password"))
    safe["sf_token_saved"]      = bool(c.get("sf_token"))
    return jsonify(safe)

@app.route("/api/creds/save", methods=["POST"])
def creds_save():
    save_creds(request.get_json())
    return jsonify({"ok": True})


# ── Routes: MSP auth + tenants ────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    base = (data.get("base") or "").strip().rstrip("/") or _msp_url()
    try:
        resp = _request_with_retry("POST", f"{base}/api/auth/login", json={"email": data["email"], "oa": True})
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Login request failed after retries: {e}"}), 502
    if not resp.ok:
        return jsonify({"error": f"Login failed: {resp.status_code} {resp.text}"}), resp.status_code
    token = resp.json().get("token")
    if not token:
        return jsonify({"error": "No token in response", "raw": resp.json()}), 500
    return jsonify({"token": token})


def _fetch_all_tenants(base, token):
    """Fetch every page of tenants from one MSP environment."""
    headers = {
        "Authorization": token,
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "Referer": f"{base}/app/tenant",
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
    }

    all_tenants = []
    page = 1
    page_size = 100

    while True:
        try:
            resp = _request_with_retry(
                "GET",
                f"{base}/api/tenants/",
                headers=headers,
                params={
                    "page": page,
                    "count": page_size,
                    "order": "desc",
                    "orderBy": "createdAt",
                    "status": ALL_STATUSES,
                },
            )
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Tenants fetch failed after retries: {e}")
        if not resp.ok:
            raise RuntimeError(f"Tenants fetch failed: {resp.status_code} {resp.text}")

        body = resp.json()
        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = body.get("data") or body.get("tenants") or body.get("items") or []
            if not isinstance(items, list):
                raise RuntimeError(f"Unexpected tenants response shape: {body}")
        else:
            break

        all_tenants.extend(items)
        if len(items) < page_size:
            break
        page += 1

    return all_tenants


@app.route("/api/tenants", methods=["POST"])
def tenants():
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400

    base = (data.get("base") or "").strip().rstrip("/") or _msp_url()
    env_label = data.get("env") or "primary"
    msp_fallback = (data.get("msp_name_fallback") or "").strip()

    try:
        all_tenants = _fetch_all_tenants(base, token)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 502

    for t in all_tenants:
        t["_env"] = env_label
        if msp_fallback and _get_msp_name(t) == "Unknown MSP":
            t["msp"] = {"name": msp_fallback}

    if all_tenants:
        print("\n=== FIRST TENANT RAW FIELDS ===")
        print(json.dumps(all_tenants[0], indent=2, default=str))
        print("================================\n")

    return jsonify({
        "tenants": all_tenants,
        "total": len(all_tenants),
        "sample": all_tenants[0] if all_tenants else None,
    })


def _tenant_id(t):
    return str(t.get("id") or t.get("_id") or t.get("tenantId") or "")


def _reconcile_new_tenants(all_tenants):
    """Auto-select brand-new tenants under MSPs that already have at least one
    currently-selected tenant (i.e. the MSP is already in production, not a POC we
    haven't vetted yet). A tenant that was seen before and deliberately deselected
    stays deselected forever — it's tracked in known_tenant_ids so it's never
    mistaken for "new" again. Persists the updated selection and known-ids set."""
    creds = load_creds()
    known_ids = set(creds.get("known_tenant_ids", []))
    selected_ids = set(creds.get("selected_tenant_ids", []))

    production_msps = {
        _get_msp_name(t) for t in all_tenants if _tenant_id(t) in selected_ids
    }

    added = []
    for t in all_tenants:
        tid = _tenant_id(t)
        if not tid or tid in known_ids:
            continue
        msp_name = _get_msp_name(t)
        if msp_name in production_msps:
            selected_ids.add(tid)
            added.append({"id": tid, "name": _get_tenant_name(t), "msp": msp_name})

    known_ids |= {_tenant_id(t) for t in all_tenants if _tenant_id(t)}

    creds["selected_tenant_ids"] = sorted(selected_ids)
    creds["known_tenant_ids"] = sorted(known_ids)
    save_creds(creds)
    return added


@app.route("/api/tenants/auto-add-new", methods=["POST"])
def tenants_auto_add_new():
    data = request.get_json()
    all_tenants = data.get("tenants", [])
    added = _reconcile_new_tenants(all_tenants)
    return jsonify({"added": added, "total_added": len(added)})


# ── Routes: Salesforce ────────────────────────────────────────────────────────

def _sf_instance_url(sf_url):
    """Convert lightning URL to My Domain API instance URL."""
    from urllib.parse import urlparse
    sf_url = (sf_url or "").strip().rstrip("/")
    if not sf_url:
        return None
    hostname = urlparse(sf_url).hostname or ""
    subdomain = hostname.split(".")[0]
    return f"https://{subdomain}.my.salesforce.com" if subdomain else None


def _get_sf(creds=None):
    from simple_salesforce import Salesforce
    if creds is None:
        creds = load_creds()

    sf_url = creds.get("sf_url", "")
    instance_url = _sf_instance_url(sf_url)

    # Preferred: session token (works even when SSO is enforced)
    session_id = creds.get("sf_session_id", "").strip()
    if session_id:
        if not instance_url:
            raise ValueError("Salesforce URL is required when using a Session Token.")
        return Salesforce(session_id=session_id, instance_url=instance_url, session=_TimeoutSession())

    # Fallback: username + password + security token
    username = creds.get("sf_username", "").strip()
    password = creds.get("sf_password", "").strip()
    if not username or not password:
        raise ValueError(
            "No Salesforce credentials found. "
            "Go to ⚙️ Settings and either capture a Session Token (Octopus SSO) "
            "or enter your Salesforce Username and Password, then click Save Settings."
        )

    domain = "test" if creds.get("sf_sandbox") else "login"
    if instance_url:
        subdomain = instance_url.split("//")[1].split(".")[0]
        domain = f"{subdomain}.my"

    return Salesforce(
        username=username,
        password=password,
        security_token=creds.get("sf_token", ""),
        domain=domain,
        session=_TimeoutSession(),
    )


@app.route("/api/sf/open-saml", methods=["POST"])
def sf_open_saml():
    """Open the Octopus SAML login URL in the user's default browser."""
    webbrowser.open(SAML_LOGIN_URL)
    return jsonify({"ok": True})


@app.route("/api/sf/receive-session", methods=["POST"])
def sf_receive_session():
    """Bookmarklet POSTs the SF session ID here after SAML auth."""
    data = request.get_json()
    session_id = (data or {}).get("session_id", "").strip()
    if not session_id:
        return jsonify({"error": "No session_id in payload"}), 400
    save_creds({"sf_session_id": session_id})
    return jsonify({"ok": True})


@app.route("/api/sf/test", methods=["POST"])
def sf_test():
    data = request.get_json()
    try:
        sf = _get_sf(data or None)
        org = sf.query("SELECT Name FROM Organization LIMIT 1")
        return jsonify({"ok": True, "org": org["records"][0]["Name"]})
    except Exception as e:
        msg = str(e)
        if "SSO_SERVICE_DOWN" in msg or "single sign on" in msg.lower():
            msg = ("SSO is enforced — username/password is blocked. "
                   "Use a Session Token instead (see the blue box above).")
        return jsonify({"error": msg}), 400


def _sync_license(sf, account_id, tenant_name, msp_name, total_users, results):
    """Create or update the License__c record linked to an Account."""
    today = date.today().strftime("%m/%d/%Y")
    license_fields = {
        "Account__c":                  account_id,
        "Organization_Name__c":        tenant_name,       # "License Name" label
        "License_Type__c":             "Enterprise",
        "Environment__c":              "SaaS",
        "Usage_Type__c":               "PROD",
        "Users__c":                    total_users,        # "Licenses Pool" label
        "Licenses_In_Use__c":          total_users,
        "License_Status__c":           "Active",
        "Managed_Service_Provider__c": msp_name,
        "Org_ID__c":                   str(random.randint(100000, 999999)),  # Text(100)
        "Comments__c":                 f"Updated by MSP Updater on {today}",
    }
    try:
        lq = f"SELECT Id FROM License__c WHERE Account__c = '{account_id}' LIMIT 1"
        lr = sf.query(lq)
        if lr["records"]:
            sf.License__c.update(lr["records"][0]["Id"], license_fields)
            results.append({
                "type": "license", "name": tenant_name, "msp": msp_name,
                "action": "updated", "detail": f"License updated · {total_users} users · {today}",
            })
        else:
            sf.License__c.create(license_fields)
            results.append({
                "type": "license", "name": tenant_name, "msp": msp_name,
                "action": "created", "detail": f"License created · {total_users} users · {today}",
            })
    except Exception as e:
        results.append({
            "type": "license", "name": tenant_name, "msp": msp_name,
            "action": "error", "detail": f"License error: {e}",
        })


# ── License history snapshots ─────────────────────────────────────────────────
# Independent of the MSP tenant sync — walks every Salesforce Account flagged
# Active_production__c (which includes on-prem / non-MSP customers like KDDI that
# have no MSP tenant record at all) and drops one License_History__c row per
# account per day, then recomputes which row is "latest" for that account's week
# and month.

def _snapshot_dates(today):
    monday = today - timedelta(days=today.weekday())
    month_first = today.replace(day=1)
    year_first = today.replace(month=1, day=1)
    return today.isoformat(), monday.isoformat(), month_first.isoformat(), year_first.isoformat()


def _reconcile_latest_flags(sf, account_id, week_str, month_str, results):
    """Idempotent, self-healing pass: for this account's current week group and
    month group, recompute from scratch (by querying every record currently in
    the group) which single record has the max Snapshot_day__c, and reconcile
    every record's flag to match that — rather than assuming the record just
    written by this run is the latest and only clearing "the others". The old
    assume-then-clear approach broke in two ways: (1) it unconditionally
    flagged the just-written record True even when an out-of-order/backfilled
    row already had a later day in the same group, and (2) a partial failure
    while clearing stale flags on other rows left duplicate True flags behind
    with no way to self-correct on a later run, since the next run would just
    assume ITS new record was the latest without ever re-checking the rest of
    the group. Recomputing the whole group from scratch every time is
    self-healing: whatever state the group is in, this converges it to exactly
    one True record (the real max day) on every single run, in insert order or
    out of it, with or without a prior partial failure."""
    for date_field, flag_field, period_value, label in [
        ("Snapshot_Week__c", "is_Latest_for_week__c", week_str, "week"),
        ("Snapshot_Month__c", "Is_Latest_For_Month__c", month_str, "month"),
    ]:
        try:
            group = sf.query_all(
                f"SELECT Id, Snapshot_day__c, CreatedDate, {flag_field} FROM License_History__c "
                f"WHERE Account__c = '{account_id}' AND {date_field} = {period_value}"
            )["records"]
        except Exception as e:
            results.append({"type": "license_history", "account_id": account_id, "action": "error",
                             "detail": f"{label} reconcile query failed: {e}"})
            continue

        dated = [r for r in group if r.get("Snapshot_day__c")]
        if not dated:
            continue  # no record in the group has a real day yet — nothing to reconcile

        max_day = max(r["Snapshot_day__c"] for r in dated)
        winners = [r for r in dated if r["Snapshot_day__c"] == max_day]
        if len(winners) > 1:
            winners.sort(key=lambda r: r["CreatedDate"], reverse=True)
            results.append({"type": "license_history", "account_id": account_id, "action": "warning",
                             "detail": f"{label} tie on {max_day}: {len(winners)} records share the max day; "
                                       f"picked most-recently-created {winners[0]['Id']}"})
        winner_id = winners[0]["Id"]

        for r in group:
            desired = (r["Id"] == winner_id)
            if bool(r.get(flag_field)) != desired:
                try:
                    sf.License_History__c.update(r["Id"], {flag_field: desired})
                except Exception as e:
                    results.append({"type": "license_history", "account_id": account_id, "action": "error",
                                     "detail": f"failed to reconcile {label} flag on {r['Id']}: {e}"})


def _upsert_license_history(sf, account_id, license_count, today_str, week_str, month_str, year_str, results):
    # Account_Month_Key__c and Active_Production__c are not writable via the API for
    # this user (INVALID_FIELD_FOR_INSERT_UPDATE) — they're populated Salesforce-side
    # (formula/Flow) from Account__c + Snapshot_Month__c, so we omit them here.
    # is_Latest_for_week__c/Is_Latest_For_Month__c are required fields but their real
    # value is decided by _reconcile_latest_flags right after, from the whole group —
    # not from assuming this new/updated record is automatically the latest.
    fields = {
        "Account__c": account_id,
        "License_Count__c": license_count or 0,
        "Snapshot_day__c": today_str,
        "Snapshot_Week__c": week_str,
        "Snapshot_Month__c": month_str,
        "Snapshot_Year__c": year_str,
        "Created_By_Job__c": "msp-portal-daily-sync",
        "is_Latest_for_week__c": False,
        "Is_Latest_For_Month__c": False,
    }
    try:
        existing = sf.query(
            f"SELECT Id FROM License_History__c WHERE Account__c = '{account_id}' "
            f"AND Snapshot_day__c = {today_str} LIMIT 1"
        )
        if existing["records"]:
            hist_id = existing["records"][0]["Id"]
            sf.License_History__c.update(hist_id, fields)
            action = "updated"
        else:
            created = sf.License_History__c.create(fields)
            hist_id = created["id"]
            action = "created"
    except Exception as e:
        results.append({"type": "license_history", "account_id": account_id, "action": "error", "detail": str(e)})
        return

    results.append({"type": "license_history", "id": hist_id, "account_id": account_id, "action": action})

    _reconcile_latest_flags(sf, account_id, week_str, month_str, results)


@app.route("/api/sf/snapshot-license-history", methods=["POST"])
def sf_snapshot_license_history():
    """Daily snapshot: copy License_Pool__c/Licenses_In_Use__c from every
    Active_production__c Salesforce Account into a new License_History__c record for
    today, and recompute the latest-for-week/latest-for-month flags for that account."""
    try:
        sf = _get_sf()
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    today_str, week_str, month_str, year_str = _snapshot_dates(date.today())

    try:
        accounts = sf.query_all(
            "SELECT Id, Name, License_Pool__c, Licenses_In_Use__c FROM Account WHERE Active_production__c = true"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    results = []
    for acc in accounts["records"]:
        license_count = acc.get("Licenses_In_Use__c")
        if license_count is None:
            license_count = acc.get("License_Pool__c") or 0
        _upsert_license_history(sf, acc["Id"], license_count, today_str, week_str, month_str, year_str, results)

    return jsonify({
        "results": results,
        "total_accounts": len(accounts["records"]),
        "created": sum(1 for r in results if r.get("action") == "created"),
        "updated": sum(1 for r in results if r.get("action") == "updated"),
        "errors": sum(1 for r in results if r.get("action") == "error"),
    })


@app.route("/api/sf/check-accounts", methods=["POST"])
def sf_check_accounts():
    """Return which account names from the given list already exist in Salesforce."""
    data = request.get_json()
    names = data.get("names", [])
    if not names:
        return jsonify({"existing": []})
    try:
        sf = _get_sf()
        batch_size = 200
        existing = []
        for i in range(0, len(names), batch_size):
            batch = names[i:i+batch_size]
            escaped = "','".join(_soql_escape(n) for n in batch)
            q = f"SELECT Name FROM Account WHERE Name IN ('{escaped}')"
            result = sf.query_all(q)
            existing.extend(r["Name"] for r in result["records"])
        return jsonify({"existing": existing})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sf/stale-accounts", methods=["POST"])
def sf_stale_accounts():
    """Return Salesforce accounts flagged Managed_By_MSP__c that no longer match any
    currently-loaded MSP tenant name — i.e. likely deleted from the MSP environment
    but still marked active/managed in Salesforce."""
    data = request.get_json()
    expected_names = set(data.get("names", []))
    try:
        sf = _get_sf()
        result = sf.query_all(
            "SELECT Id, Name, ParentId, Parent.Name, Active_production__c, Managed_By_MSP__c, "
            "License_Pool__c, Licenses_In_Use__c FROM Account WHERE Managed_By_MSP__c = true"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    stale = []
    for r in result["records"]:
        if r["Name"] in expected_names:
            continue
        parent = r.get("Parent") or {}
        stale.append({
            "id": r["Id"],
            "name": r["Name"],
            "msp_name": parent.get("Name") or "",
            "active_production": bool(r.get("Active_production__c")),
            "managed_by_msp": bool(r.get("Managed_By_MSP__c")),
            "license_pool": r.get("License_Pool__c"),
            "licenses_in_use": r.get("Licenses_In_Use__c"),
        })
    return jsonify({"stale": stale, "total_checked": len(result["records"])})


@app.route("/api/sf/deactivate", methods=["POST"])
def sf_deactivate():
    """Clear Active_production__c and Managed_By_MSP__c on the given Salesforce Account
    ids — used to unwind accounts for tenants that no longer exist in the MSP environment."""
    data = request.get_json()
    account_ids = data.get("account_ids", [])
    if not account_ids:
        return jsonify({"error": "No account_ids provided"}), 400
    try:
        sf = _get_sf()
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    results = []
    for account_id in account_ids:
        try:
            sf.Account.update(account_id, {"Active_production__c": False, "Managed_By_MSP__c": False})
            results.append({"id": account_id, "action": "deactivated"})
        except Exception as e:
            results.append({"id": account_id, "action": "error", "detail": str(e)})
    return jsonify({"results": results})


@app.route("/api/sf/sync", methods=["POST"])
def sf_sync():
    data = request.get_json()
    tenants_list = data.get("tenants", [])

    try:
        sf = _get_sf()
    except Exception as e:
        msg = str(e)
        if "SSO_SERVICE_DOWN" in msg or "single sign on" in msg.lower():
            msg = ("SSO is enforced on this Salesforce org — username/password login is blocked. "
                   "Go to ⚙️ Settings and paste a Session Token. "
                   "Get it from Salesforce: Setup → Developer Console → Debug → "
                   "Open Execute Anonymous Window → run: System.debug(UserInfo.getSessionId()); "
                   "→ copy the value from the log output.")
        return jsonify({"error": msg}), 400

    results = []
    msp_name_map    = data.get("msp_name_map", {})     # portal MSP name → SF account name
    tenant_name_map = data.get("tenant_name_map", {})  # tenant ID → SF account name

    # Find "SDO - MSP" parent account ID
    sdo_result = sf.query("SELECT Id FROM Account WHERE Name = 'SDO - MSP' LIMIT 1")
    sdo_msp_id = sdo_result["records"][0]["Id"] if sdo_result["records"] else None
    if not sdo_msp_id:
        results.append({"type": "warning", "name": "SDO - MSP", "action": "not_found",
                        "detail": "'SDO - MSP' account not found — MSP parent accounts will not be linked"})

    # Group tenants by MSP
    groups = {}
    for t in tenants_list:
        msp_name = _get_msp_name(t)
        groups.setdefault(msp_name, []).append(t)

    msp_id_cache = {}

    for msp_name in sorted(groups.keys()):
        msp_tenants = groups[msp_name]
        sf_msp_name = msp_name_map.get(msp_name, msp_name) or msp_name  # use override if provided

        # ── Step 1: Verify/update MSP account ──
        q = f"SELECT Id, ParentId FROM Account WHERE Name = '{_soql_escape(sf_msp_name)}' LIMIT 1"
        try:
            msp_result = sf.query(q)
        except Exception as e:
            results.append({"type": "msp", "name": msp_name, "action": "error", "detail": str(e)})
            msp_id_cache[msp_name] = None
            continue

        name_note = f" (mapped from '{msp_name}')" if sf_msp_name != msp_name else ""
        if msp_result["records"]:
            msp_acc = msp_result["records"][0]
            msp_id = msp_acc["Id"]
            msp_id_cache[msp_name] = msp_id

            msp_update = {"Type": "Managed Service Provider (MSP)"}
            if sdo_msp_id and msp_acc.get("ParentId") != sdo_msp_id:
                msp_update["ParentId"] = sdo_msp_id
            try:
                sf.Account.update(msp_id, msp_update)
                detail = "Type set · " + (f"Parent set to SDO - MSP{name_note}" if "ParentId" in msp_update else f"Parent already correct{name_note}")
                results.append({"type": "msp", "name": sf_msp_name, "msp": msp_name, "action": "updated", "detail": detail})
            except Exception as e:
                results.append({"type": "msp", "name": sf_msp_name, "msp": msp_name, "action": "error", "detail": str(e)})
        else:
            msp_id_cache[msp_name] = None
            results.append({"type": "msp", "name": sf_msp_name, "msp": msp_name, "action": "not_found",
                            "detail": f"Account not found in Salesforce{name_note} — skipping parent link for tenants"})

        msp_id = msp_id_cache.get(msp_name)

        # ── Step 2: Process each tenant ──
        for t in msp_tenants:
            tenant_id   = str(t.get("id") or t.get("_id") or t.get("tenantId") or "")
            tenant_name = _get_tenant_name(t)
            sf_tenant_name = (tenant_name_map.get(tenant_id) or "").strip() or tenant_name
            name_note = f" (mapped from '{tenant_name}')" if sf_tenant_name != tenant_name else ""

            users_obj = t.get("usersCount") or {}
            total_users      = users_obj.get("total", 0)      if isinstance(users_obj, dict) else 0
            enterprise_users = users_obj.get("enterprise", 0) if isinstance(users_obj, dict) else 0
            starter_users    = users_obj.get("starters", 0)   if isinstance(users_obj, dict) else 0

            update_fields = {
                "Type":                 "Managed Service Provider (MSP)",
                "License_Pool__c":      total_users,
                "Licenses_In_Use__c":   total_users,
                "Active_production__c": True,
                "Managed_By_MSP__c":    True,
            }
            if msp_id:
                update_fields["ParentId"] = msp_id

            tq = f"SELECT Id FROM Account WHERE Name = '{_soql_escape(sf_tenant_name)}' LIMIT 1"
            try:
                t_result = sf.query(tq)
                if t_result["records"]:
                    account_id = t_result["records"][0]["Id"]
                    sf.Account.update(account_id, update_fields)
                    results.append({
                        "type": "tenant", "name": sf_tenant_name, "msp": msp_name,
                        "action": "updated",
                        "detail": f"Users: {total_users} total · {enterprise_users} enterprise · {starter_users} starter{name_note}",
                    })
                else:
                    update_fields["Name"] = sf_tenant_name
                    created = sf.Account.create(update_fields)
                    account_id = created.get("id")
                    results.append({
                        "type": "tenant", "name": sf_tenant_name, "msp": msp_name,
                        "action": "created",
                        "detail": f"Users: {total_users} total · {enterprise_users} enterprise · {starter_users} starter",
                    })

                # ── Create / update License record for this account ──
                if account_id:
                    _sync_license(sf, account_id, sf_tenant_name, sf_msp_name, total_users, results)

            except Exception as e:
                results.append({
                    "type": "tenant", "name": tenant_name, "msp": msp_name,
                    "action": "error", "detail": str(e),
                })

    return jsonify({"results": results, "total": len(results)})


if __name__ == "__main__":
    app.run(debug=True, port=5070)
