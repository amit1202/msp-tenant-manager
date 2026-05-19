import json
import os
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)
app.secret_key = "msp-portal-secret-key"

BASE_URL = "https://msp.doubleoctopus.io/mt"
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


# ── Routes: credentials ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/creds/load", methods=["GET"])
def creds_load():
    c = load_creds()
    # Never return SF password back to browser
    safe = {k: v for k, v in c.items() if k not in ("sf_password", "sf_token")}
    return jsonify(safe)

@app.route("/api/creds/save", methods=["POST"])
def creds_save():
    save_creds(request.get_json())
    return jsonify({"ok": True})


# ── Routes: MSP auth + tenants ────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    resp = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": data["email"], "oa": True},
        timeout=15,
    )
    if not resp.ok:
        return jsonify({"error": f"Login failed: {resp.status_code} {resp.text}"}), resp.status_code
    token = resp.json().get("token")
    if not token:
        return jsonify({"error": "No token in response", "raw": resp.json()}), 500
    return jsonify({"token": token})


@app.route("/api/tenants", methods=["POST"])
def tenants():
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400

    headers = {
        "Authorization": token,
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "Referer": f"{BASE_URL}/app/tenant",
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
    }

    all_tenants = []
    page = 1
    page_size = 100

    while True:
        resp = requests.get(
            f"{BASE_URL}/api/tenants/",
            headers=headers,
            params={
                "page": page,
                "count": page_size,
                "order": "desc",
                "orderBy": "createdAt",
                "status": ALL_STATUSES,
            },
            timeout=15,
        )
        if not resp.ok:
            return jsonify({"error": f"Tenants fetch failed: {resp.status_code} {resp.text}"}), resp.status_code

        body = resp.json()
        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = body.get("data") or body.get("tenants") or body.get("items") or []
            if not isinstance(items, list):
                return jsonify({"raw": body})
        else:
            break

        all_tenants.extend(items)
        if len(items) < page_size:
            break
        page += 1

    if all_tenants:
        print("\n=== FIRST TENANT RAW FIELDS ===")
        print(json.dumps(all_tenants[0], indent=2, default=str))
        print("================================\n")

    return jsonify({
        "tenants": all_tenants,
        "total": len(all_tenants),
        "sample": all_tenants[0] if all_tenants else None,
    })


# ── Routes: Salesforce ────────────────────────────────────────────────────────

def _get_sf(creds=None):
    from simple_salesforce import Salesforce
    from urllib.parse import urlparse
    if creds is None:
        creds = load_creds()

    # Derive My Domain from the SF URL if provided
    # e.g. https://secretdoubleoctopus.lightning.force.com/ → domain = 'secretdoubleoctopus.my'
    domain = "test" if creds.get("sf_sandbox") else "login"
    sf_url = creds.get("sf_url", "").strip().rstrip("/")
    if sf_url:
        hostname = urlparse(sf_url).hostname or ""
        subdomain = hostname.split(".")[0]
        if subdomain:
            domain = f"{subdomain}.my"

    return Salesforce(
        username=creds["sf_username"],
        password=creds["sf_password"],
        security_token=creds.get("sf_token", ""),
        domain=domain,
    )


@app.route("/api/sf/test", methods=["POST"])
def sf_test():
    data = request.get_json()
    try:
        sf = _get_sf(data)
        org = sf.query("SELECT Name FROM Organization LIMIT 1")
        return jsonify({"ok": True, "org": org["records"][0]["Name"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sf/sync", methods=["POST"])
def sf_sync():
    data = request.get_json()
    tenants_list = data.get("tenants", [])

    try:
        sf = _get_sf()
    except Exception as e:
        return jsonify({"error": f"Salesforce auth failed: {e}"}), 400

    results = []

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

        # ── Step 1: Verify/update MSP account ──
        q = f"SELECT Id, ParentId FROM Account WHERE Name = '{_soql_escape(msp_name)}' LIMIT 1"
        try:
            msp_result = sf.query(q)
        except Exception as e:
            results.append({"type": "msp", "name": msp_name, "action": "error", "detail": str(e)})
            msp_id_cache[msp_name] = None
            continue

        if msp_result["records"]:
            msp_acc = msp_result["records"][0]
            msp_id = msp_acc["Id"]
            msp_id_cache[msp_name] = msp_id

            if sdo_msp_id and msp_acc.get("ParentId") != sdo_msp_id:
                try:
                    sf.Account.update(msp_id, {"ParentId": sdo_msp_id})
                    results.append({"type": "msp", "name": msp_name, "action": "updated",
                                    "detail": "Parent set to SDO - MSP"})
                except Exception as e:
                    results.append({"type": "msp", "name": msp_name, "action": "error", "detail": str(e)})
            else:
                results.append({"type": "msp", "name": msp_name, "action": "ok",
                                "detail": "Verified — parent already correct"})
        else:
            msp_id_cache[msp_name] = None
            results.append({"type": "msp", "name": msp_name, "action": "not_found",
                            "detail": "Account not found in Salesforce — skipping parent link for tenants"})

        msp_id = msp_id_cache.get(msp_name)

        # ── Step 2: Process each tenant ──
        for t in msp_tenants:
            tenant_name = _get_tenant_name(t)
            users_obj = t.get("usersCount") or {}
            total_users     = users_obj.get("total", 0)      if isinstance(users_obj, dict) else 0
            enterprise_users = users_obj.get("enterprise", 0) if isinstance(users_obj, dict) else 0
            starter_users   = users_obj.get("starters", 0)   if isinstance(users_obj, dict) else 0

            update_fields = {
                "License_Pool__c":      total_users,
                "Licenses_In_Use__c":   total_users,
                "Active_production__c": True,
                "Managed_By_MSP__c":    True,
            }
            if msp_id:
                update_fields["ParentId"] = msp_id

            tq = f"SELECT Id FROM Account WHERE Name = '{_soql_escape(tenant_name)}' LIMIT 1"
            try:
                t_result = sf.query(tq)
                if t_result["records"]:
                    sf.Account.update(t_result["records"][0]["Id"], update_fields)
                    results.append({
                        "type": "tenant", "name": tenant_name, "msp": msp_name,
                        "action": "updated",
                        "detail": f"Users: {total_users} total · {enterprise_users} enterprise · {starter_users} starter",
                    })
                else:
                    update_fields["Name"] = tenant_name
                    sf.Account.create(update_fields)
                    results.append({
                        "type": "tenant", "name": tenant_name, "msp": msp_name,
                        "action": "created",
                        "detail": f"Users: {total_users} total · {enterprise_users} enterprise · {starter_users} starter",
                    })
            except Exception as e:
                results.append({
                    "type": "tenant", "name": tenant_name, "msp": msp_name,
                    "action": "error", "detail": str(e),
                })

    return jsonify({"results": results, "total": len(results)})


if __name__ == "__main__":
    app.run(debug=True, port=5050)
