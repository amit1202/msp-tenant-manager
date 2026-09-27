#!/usr/bin/env python3
"""Standalone daily sync driver: logs into every configured MSP environment, fetches tenants,
filters to the currently saved tenant selection, and syncs to Salesforce via the app's own
/api/login, /api/tenants and /api/sf/sync routes (invoked in-process, no server needed).
Reads credentials.json fresh on every run."""
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app as flask_app, load_creds

# The MSP login is approved by a push on the phone; if nobody approves it the login
# times out. Instead of skipping the whole day, wait and try again.
LOGIN_ATTEMPTS = 3            # 18:00, 18:30, 19:00
LOGIN_RETRY_DELAY_SECONDS = 30 * 60


class LoginFailed(RuntimeError):
    pass


def login_and_fetch(client, email, base, env_label, msp_name_fallback=""):
    login_resp = client.post("/api/login", json={"email": email, "base": base})
    login_data = login_resp.get_json()
    if login_resp.status_code != 200 or not login_data or login_data.get("error"):
        raise LoginFailed(f"[{env_label}] login failed: {login_data}")

    ten_resp = client.post("/api/tenants", json={"token": login_data["token"], "base": base, "env": env_label, "msp_name_fallback": msp_name_fallback})
    ten_data = ten_resp.get_json()
    if ten_resp.status_code != 200 or not ten_data or ten_data.get("error"):
        raise RuntimeError(f"[{env_label}] tenants fetch failed: {ten_data}")
    return ten_data.get("tenants", [])


def main():
    print(f"=== Daily sync started {datetime.now().isoformat()} ===")
    creds = load_creds()
    email = creds.get("msp_email", "").strip()
    if not email:
        print("ERROR: no msp_email saved in credentials.json — aborting")
        sys.exit(1)

    selected_ids = set(creds.get("selected_tenant_ids", []))
    if not selected_ids:
        print("ERROR: no selected_tenant_ids saved in credentials.json — aborting")
        sys.exit(1)

    with flask_app.test_client() as client:
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            print(f"Logging into primary MSP environment as {email} (attempt {attempt}/{LOGIN_ATTEMPTS})...", flush=True)
            try:
                tenants = login_and_fetch(client, email, creds.get("msp_url", ""), "primary")
                break
            except LoginFailed as e:
                if attempt == LOGIN_ATTEMPTS:
                    print(f"ERROR: {e} — giving up after {LOGIN_ATTEMPTS} attempts", flush=True)
                    raise
                print(f"WARNING: {e} — retrying in {LOGIN_RETRY_DELAY_SECONDS // 60} minutes "
                      f"(approve the push on your phone)", flush=True)
                time.sleep(LOGIN_RETRY_DELAY_SECONDS)
        print(f"Fetched {len(tenants)} tenants from primary")

        url_2 = (creds.get("msp_url_2") or "").strip()
        email_2 = (creds.get("msp_email_2") or "").strip()
        name_2 = (creds.get("msp_name_2") or "").strip()
        if url_2 and email_2:
            print(f"Logging into secondary MSP environment ({url_2}) as {email_2}...")
            try:
                secondary_tenants = login_and_fetch(client, email_2, url_2, "secondary", name_2)
                print(f"Fetched {len(secondary_tenants)} tenants from secondary")
                tenants += secondary_tenants
            except RuntimeError as e:
                print(f"WARNING: secondary environment failed, continuing with primary only: {e}")

    print(f"Fetched {len(tenants)} tenants total")

    with flask_app.test_client() as client:
        reconcile_resp = client.post("/api/tenants/auto-add-new", json={"tenants": tenants})
        reconcile_data = reconcile_resp.get_json() or {}
    added = reconcile_data.get("added", [])
    if added:
        print(f"Auto-added {len(added)} new tenant(s) under already-production MSPs:")
        for a in added:
            print(f"  + {a['name']} ({a['msp']})")
    else:
        print("No new tenants to auto-add.")

    # selected_tenant_ids may have just changed above — reload before filtering
    creds = load_creds()
    selected_ids = set(creds.get("selected_tenant_ids", []))

    selected = [t for t in tenants if str(t.get("id") or t.get("_id") or t.get("tenantId") or "") in selected_ids]
    print(f"{len(selected)} of {len(selected_ids)} saved-selected tenant IDs matched a live tenant")

    with flask_app.test_client() as client:
        resp = client.post(
            "/api/sf/sync",
            json={
                "tenants": selected,
                "msp_name_map": creds.get("msp_name_map", {}),
                "tenant_name_map": creds.get("tenant_name_map", {}),
            },
        )
        data = resp.get_json()

    if resp.status_code != 200 or data is None:
        print(f"ERROR: sync request failed (HTTP {resp.status_code}): {data}")
        sys.exit(1)

    results = data.get("results", [])
    created = sum(1 for r in results if r.get("action") == "created")
    updated = sum(1 for r in results if r.get("action") == "updated")
    errors = [r for r in results if r.get("action") == "error"]
    not_found = [r for r in results if r.get("action") == "not_found"]

    print(f"\n=== SYNC SUMMARY ===")
    print(f"Created: {created}  Updated: {updated}  Errors: {len(errors)}  Not found: {len(not_found)}")
    for r in errors:
        print(f"ERROR [{r.get('type')}] {r.get('name')}: {r.get('detail')}")
    for r in not_found:
        print(f"NOT FOUND [{r.get('type')}] {r.get('name')}: {r.get('detail')}")

    print(f"\n=== License history snapshot {datetime.now().isoformat()} ===")
    with flask_app.test_client() as client:
        hist_resp = client.post("/api/sf/snapshot-license-history")
        hist_data = hist_resp.get_json()
    if hist_resp.status_code != 200 or hist_data is None:
        print(f"ERROR: license history snapshot failed (HTTP {hist_resp.status_code}): {hist_data}")
    else:
        print(f"Accounts checked: {hist_data.get('total_accounts')}  "
              f"Created: {hist_data.get('created')}  Updated: {hist_data.get('updated')}  Errors: {hist_data.get('errors')}")
        for r in hist_data.get("results", []):
            if r.get("action") == "error":
                print(f"ERROR [license_history] {r.get('account_id')}: {r.get('detail')}")

    print(f"=== Daily sync finished {datetime.now().isoformat()} ===")


if __name__ == "__main__":
    main()
