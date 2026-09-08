#!/usr/bin/env python3
"""One-time backfill for a single Snapshot_Week__c group of License_History__c.

Why this exists: the normal daily reconcile (app._reconcile_latest_flags, run as part
of /api/sf/snapshot-license-history) only touches the accounts the daily sync processes
that day. The week of 2026-08-31 was left with stale is_Latest_for_week__c flags because
(a) two of the seven daily runs that week (2026-09-03, 2026-09-04) crashed before ever
reaching the reconcile step (MSP login hang — see logs/daily_sync.err.log), and (b) the
reconcile logic itself was rewritten mid-week to fix a duplicate/stale-flag bug, so the
early-week runs used the old, buggy version. Net effect: only 106 of 478 accounts ended
up with a correct is_Latest_for_week__c = true record for that week.

This script re-derives, from scratch, the correct latest-day record for every account
that has ANY License_History__c row in the given week (not just the accounts the daily
sync currently covers), and reconciles is_Latest_for_week__c to match — using the same
self-healing approach as app._reconcile_latest_flags, just run once for a whole week
group instead of per-account-per-day.

Usage:
    python3 backfill_latest_week_flags.py 2026-08-31 [--apply]

Without --apply it only prints what would change (dry run). Pass --apply to actually
write the updates to Salesforce.
"""
import sys

from app import _get_sf


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    apply = "--apply" in sys.argv
    if len(args) != 1:
        print("Usage: python3 backfill_latest_week_flags.py YYYY-MM-DD [--apply]")
        sys.exit(1)
    week_str = args[0]

    sf = _get_sf()

    print(f"Querying License_History__c for Snapshot_Week__c = {week_str} ...")
    records = sf.query_all(
        f"SELECT Id, Account__c, Snapshot_day__c, CreatedDate, is_Latest_for_week__c "
        f"FROM License_History__c "
        f"WHERE Snapshot_Week__c = {week_str} AND Account__c != null"
    )["records"]
    print(f"Fetched {len(records)} records.")

    by_account = {}
    for r in records:
        by_account.setdefault(r["Account__c"], []).append(r)

    updates = []
    warnings = []
    for account_id, group in by_account.items():
        dated = [r for r in group if r.get("Snapshot_day__c")]
        if not dated:
            continue
        max_day = max(r["Snapshot_day__c"] for r in dated)
        winners = [r for r in dated if r["Snapshot_day__c"] == max_day]
        if len(winners) > 1:
            winners.sort(key=lambda r: r["CreatedDate"], reverse=True)
            warnings.append(
                f"{account_id}: tie on {max_day}, {len(winners)} records — "
                f"picked most-recently-created {winners[0]['Id']}"
            )
        winner_id = winners[0]["Id"]

        for r in group:
            desired = (r["Id"] == winner_id)
            if bool(r.get("is_Latest_for_week__c")) != desired:
                updates.append({"Id": r["Id"], "is_Latest_for_week__c": desired})

    print(f"\n{len(by_account)} accounts checked.")
    print(f"{len(updates)} record(s) need a flag change.")
    for w in warnings:
        print(f"WARN  {w}")

    if not updates:
        print("Nothing to do.")
        return

    if not apply:
        print("\nDry run only — pass --apply to write these changes to Salesforce.")
        for u in updates[:20]:
            print(f"  {u['Id']}: is_Latest_for_week__c -> {u['is_Latest_for_week__c']}")
        if len(updates) > 20:
            print(f"  ... and {len(updates) - 20} more")
        return

    print(f"\nApplying {len(updates)} update(s) in batches of 200 ...")
    errors = 0
    for i in range(0, len(updates), 200):
        batch = updates[i:i + 200]
        results = sf.bulk.License_History__c.update(batch)
        for rec, res in zip(batch, results):
            if not res.get("success"):
                errors += 1
                print(f"ERROR updating {rec['Id']}: {res.get('errors')}")
    print(f"Done. {len(updates) - errors} succeeded, {errors} failed.")


if __name__ == "__main__":
    main()
