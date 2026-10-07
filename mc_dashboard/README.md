# Octopus MC live status dashboard

A management dashboard for an Octopus Management Console:
- Enrolled and active users
- Authentications over the last 30 days, split into applications vs. Windows/macOS workstations, including
  FIDO2/passkey sign-ins and the authenticator used for each sign-in
- A live feed of recent sign-ins and today's counts
- The top 5 users, protected services, system health and errors

Search a user at the top to switch the whole dashboard to that person. Their authentications, applications,
workstations, directory accounts and failed sign-ins replace the system-wide numbers. Standard-library
Python, no dependencies.

## Setup

1. In the MC, create an API client (**Security → Clients**) that can read settings, directories, services,
   workstations and audit logs.
2. Start the server and open **Settings** (`http://127.0.0.1:8088/settings`, only reachable from this machine).
   Enter the MC host, client ID and secret, click **Test connection**, then **Save**.
   The settings are stored in `~/.config/mc-dashboard/config.json` with owner-only permissions. You can
   also copy `config.example.json` there by hand, or set `MC_HOST`, `MC_CLIENT_ID` and `MC_CLIENT_SECRET`.

```
python3 server.py                         # http://127.0.0.1:8088
python3 server.py --check                 # test credentials and API access from the command line
python3 server.py --snapshot status.html  # self-contained HTML file you can email or attach
```

## How it stays light on the MC

- On startup the server loads the whole window (30 days by default) once. It only reads the event
  types the dashboard uses: Octopus authentications, workstation logons and unlocks, and errors.
- Every refresh (default **every 5 minutes**, configurable from 1 to 60) fetches only the events since
  the last refresh, plus a 10-minute overlap to catch late events.
- **Refresh now** on the dashboard fetches immediately. Clicks within 30 seconds of the last refresh reuse
  that refresh's result.
- Per-user views are computed from data already in memory. The only extra call is a cached MC lookup
  of the user's directory accounts.

## Sharing with management

In Settings, set **Listen on → Office network**, generate an **Access key**, save, and restart the server.
Then share `http://<this-machine>:8088/?key=<key>`. Opening `?user=<username>` goes straight to a user.
Settings can only be opened on the machine running the server. The page lists usernames, so don't expose
it to the internet. **Download snapshot** saves an offline copy of the current view, including a
per-user view.

## Metric definitions

| Metric | Source |
|---|---|
| Enrolled users | Sum of `activeCount` over all directories (`/directories/:id/members`) |
| Active users | Distinct users with at least one successful authentication in the window |
| Application authentications | Audit `Octopus authentication` events, excluding workstation-logon services |
| Workstation authentications | Desktop-agent `Unlock` / `Logon` success events (Mac and Windows Workstation sources). Some agents never upload their own events; for those, the server-side workstation logon is counted instead, on the machine named in the session's "Update Workstation" event (base64 name after the hardware ID) |
| Workstations | `/workstations`, grouped by OS. Active = distinct devices that signed in during the window |
| Services | `/services` totals |
| System errors | Audit events at `error` level. Failed sign-ins = failed/denied `Octopus authentication` events |
| System health | `/settings/status` |

| Passkey (FIDO2) sign-ins | FIDO Server `FIDO2 assertion` "User authenticated" events (these never produce an `Octopus authentication` event). The app is the `SAML login (id)` in the same session; "Logged in from FIDO Server" means the user portal |
| Authenticator per sign-in | Evidence in the sign-in's session (all sources share its `sessionId`): FIDO assertion → Passkey; push approval (`User selected "Approve"`) → Octopus push, plus a phone biometric check → push + biometrics; BLE events → offline BLE; "Adaptive Authentication" or a workstation logon accepted with no prompt → trusted device. LDAP/RADIUS events have no `sessionId`, so they are matched to the same user's push/biometric events within 30 seconds |

A workstation logon also creates an `Octopus authentication` event for the "Active Directory
Authentication" service. Those events count toward active users only, so logons aren't counted twice.
By default the excluded services are ADPA services whose name starts with "Active Directory". To change
the list, set `workstationServices` in the config.
