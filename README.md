# MSP Tenant Manager

A web app that connects to the Double Octopus MSP Tenant Manager, pulls the full list of MSPs and their tenants, and lets you view and export the data to Excel.

## Features

- Octopus Authentication (OA) — email only, no password
- Tree view grouped by MSP with collapsible sections
- Per-tenant: ID, name, domain, status, active/enterprise/starter user counts, created date
- Summary totals across all MSPs
- Search/filter across all tenants and MSPs
- One-click Excel export (two sheets: all tenants + MSP summary)

## Requirements

- Python 3.8+
- pip3

## Run

```bash
chmod +x run.sh
./run.sh
```

Then open **http://localhost:5050** in your browser.

## Manual start

```bash
pip3 install -r requirements.txt
python3 app.py
```

## API

Connects to: `https://msp.doubleoctopus.io/mt`

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/auth/login` | POST | Get bearer token (`oa: true`) |
| `/api/tenants/` | GET | Fetch all tenants (paginated) |
