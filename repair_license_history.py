#!/usr/bin/env python3
"""One-time repair of License_History__c after the AccountLicenseWeekly Flow and the
msp-portal daily job disagreed about week start and "latest" flags.

Rules (same as the fixed Flow, which now owns these fields):
  * Snapshot_Week__c  = the SUNDAY on/before Snapshot_day__c
  * Snapshot_Month__c = 1st of Snapshot_day__c's month, Snapshot_Year__c = Jan 1st
  * is_Latest_for_week__c  = true only on the max-Snapshot_day__c row per account + week
  * Is_Latest_For_Month__c = true only on the max-Snapshot_day__c row per account + month

Legacy rows (2025 monthly history bulk-loaded on 2026-01-20: Snapshot_day__c = 2026-01-20
but Snapshot_Month__c in 2025) keep their period fields; they only take part in the
month-flag calculation and never carry a week flag.

Deleted (soft delete -> Recycle Bin):
  * rows with no Snapshot_day__c (created by the old "Account license history" Flow)
  * rows with no Account__c (account deleted / merged)
  * extra rows for the same account + day (keeps the msp-portal-refreshed one, else the oldest)

Usage:
    python3 repair_license_history.py            # dry run, prints the plan
    python3 repair_license_history.py --apply    # writes to Salesforce
"""
import sys
from collections import Counter, defaultdict
from datetime import date, timedelta

from app import _get_sf

LEGACY_LOAD_DAY = "2026-01-20"


def is_legacy(r):
    return r["Snapshot_day__c"] == LEGACY_LOAD_DAY and (r["Snapshot_Month__c"] or "") < "2026-01-01"


def periods(day_str):
    d = date.fromisoformat(day_str)
    week = d - timedelta(days=(d.weekday() + 1) % 7)
    return week.isoformat(), d.replace(day=1).isoformat(), d.replace(month=1, day=1).isoformat()


def pick_winner(group):
    max_day = max(r["Snapshot_day__c"] for r in group)
    return max((r for r in group if r["Snapshot_day__c"] == max_day), key=lambda r: r["CreatedDate"])["Id"]


def main():
    apply = "--apply" in sys.argv
    sf = _get_sf()
    rows = sf.query_all(
        "SELECT Id, Name, Account__c, Snapshot_day__c, Snapshot_Week__c, Snapshot_Month__c, Snapshot_Year__c, "
        "is_Latest_for_week__c, Is_Latest_For_Month__c, CreatedDate, Created_By_Job__c FROM License_History__c"
    )["records"]
    print(f"Fetched {len(rows)} License_History__c rows")

    deletes = {}
    for r in rows:
        if not r["Snapshot_day__c"]:
            deletes[r["Id"]] = "no Snapshot_day__c"
        elif not r["Account__c"]:
            deletes[r["Id"]] = "no Account__c"

    by_day = defaultdict(list)
    for r in rows:
        if r["Id"] not in deletes and not is_legacy(r):
            by_day[(r["Account__c"], r["Snapshot_day__c"])].append(r)
    for group in by_day.values():
        if len(group) > 1:
            group.sort(key=lambda r: (r["Created_By_Job__c"] != "msp-portal-daily-sync", r["CreatedDate"]))
            for r in group[1:]:
                deletes[r["Id"]] = f"duplicate of {group[0]['Name']} for {r['Snapshot_day__c']}"

    keep = [r for r in rows if r["Id"] not in deletes]

    # Target period fields
    target = {}
    for r in keep:
        if is_legacy(r):
            target[r["Id"]] = {"week": r["Snapshot_Week__c"], "month": r["Snapshot_Month__c"], "year": r["Snapshot_Year__c"]}
        else:
            w, m, y = periods(r["Snapshot_day__c"])
            target[r["Id"]] = {"week": w, "month": m, "year": y}

    weeks, months = defaultdict(list), defaultdict(list)
    for r in keep:
        t = target[r["Id"]]
        months[(r["Account__c"], t["month"])].append(r)
        if not is_legacy(r):
            weeks[(r["Account__c"], t["week"])].append(r)
    week_winners = {pick_winner(g) for g in weeks.values()}
    month_winners = {pick_winner(g) for g in months.values()}

    updates, reasons = [], Counter()
    for r in keep:
        t, u = target[r["Id"]], {}
        if r["Snapshot_Week__c"] != t["week"]:
            u["Snapshot_Week__c"] = t["week"]; reasons["Snapshot_Week__c"] += 1
        if r["Snapshot_Month__c"] != t["month"]:
            u["Snapshot_Month__c"] = t["month"]; reasons["Snapshot_Month__c"] += 1
        if r["Snapshot_Year__c"] != t["year"]:
            u["Snapshot_Year__c"] = t["year"]; reasons["Snapshot_Year__c"] += 1
        wk = r["Id"] in week_winners
        if bool(r["is_Latest_for_week__c"]) != wk:
            u["is_Latest_for_week__c"] = wk; reasons[f"is_Latest_for_week__c -> {wk}"] += 1
        mo = r["Id"] in month_winners
        if bool(r["Is_Latest_For_Month__c"]) != mo:
            u["Is_Latest_For_Month__c"] = mo; reasons[f"Is_Latest_For_Month__c -> {mo}"] += 1
        if u:
            u["Id"] = r["Id"]
            updates.append(u)

    print(f"\nDeletes: {len(deletes)}")
    for reason, n in Counter(v if not v.startswith("duplicate") else "same-day duplicate" for v in deletes.values()).items():
        print(f"  {n:6}  {reason}")
    print(f"\nUpdates: {len(updates)} rows")
    for reason, n in sorted(reasons.items()):
        print(f"  {n:6}  {reason}")
    print(f"\nAfter repair: {len(weeks)} account-weeks and {len(months)} account-months, each with exactly one latest row")

    if not apply:
        print("\nDry run only - pass --apply to write these changes to Salesforce.")
        return

    errors = 0
    for i in range(0, len(updates), 200):
        batch = updates[i:i + 200]
        for rec, res in zip(batch, sf.bulk.License_History__c.update(batch)):
            if not res.get("success"):
                errors += 1
                print(f"ERROR updating {rec['Id']}: {res.get('errors')}")
    ids = [{"Id": i} for i in deletes]
    for i in range(0, len(ids), 200):
        batch = ids[i:i + 200]
        for rec, res in zip(batch, sf.bulk.License_History__c.delete(batch)):
            if not res.get("success"):
                errors += 1
                print(f"ERROR deleting {rec['Id']}: {res.get('errors')}")
    print(f"Done. {len(updates)} updates, {len(deletes)} deletes, {errors} errors.")


if __name__ == "__main__":
    main()
