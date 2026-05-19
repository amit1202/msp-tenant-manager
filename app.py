from flask import Flask, request, jsonify, render_template, session
import requests

app = Flask(__name__)
app.secret_key = "msp-portal-secret-key"

BASE_URL = "https://msp.doubleoctopus.io/mt"
ALL_STATUSES = "INIT,INIT_DOMAIN_ALLOCATION,INIT_MC_SETUP,LIVE,ERROR,ERROR_SUBDOMAIN_REGISTRATION,SUSPENDED,MIGRATING,ERROR_SUBDOMAIN_RESTORE,DNS_UPDATING"


@app.route("/")
def index():
    return render_template("index.html")


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

        # Handle common response shapes: {data: [...]} or {tenants: [...]} or plain list
        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = body.get("data") or body.get("tenants") or body.get("items") or []
            if not isinstance(items, list):
                # Return raw so we can inspect
                return jsonify({"raw": body})
        else:
            break

        all_tenants.extend(items)

        # Stop if we got fewer items than requested (last page)
        if len(items) < page_size:
            break
        page += 1

    if all_tenants:
        import json
        print("\n=== FIRST TENANT RAW FIELDS ===")
        print(json.dumps(all_tenants[0], indent=2, default=str))
        print("================================\n")

    return jsonify({
        "tenants": all_tenants,
        "total": len(all_tenants),
        "sample": all_tenants[0] if all_tenants else None,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5050)
