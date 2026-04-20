#!/usr/bin/env python3
import datetime
import os
import sqlite3
import sys

HISTORY_DEFAULT = os.path.join(
    "AppData",
    "Local",
    "Microsoft",
    "Edge",
    "User Data",
    "Default",
    "History",
)

EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def chrome_us_to_utc_iso(ts_us: int) -> str:
    dt = EPOCH_1601 + datetime.timedelta(microseconds=ts_us)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_last_malicious_visit(history_path: str):
    query = """
    SELECT u.url, u.title, v.visit_time
    FROM visits v
    JOIN urls u ON u.id = v.url
    WHERE u.url LIKE '%23.179.17.92%'
       OR u.url LIKE '%downloadmoreram%'
       OR u.title LIKE '%Download More RAM%'
    ORDER BY v.visit_time DESC
    LIMIT 1;
    """

    con = sqlite3.connect(history_path)
    try:
        cur = con.cursor()
        cur.execute(query)
        row = cur.fetchone()
        return row
    finally:
        con.close()


def main():
    history_path = HISTORY_DEFAULT
    if len(sys.argv) > 1:
        history_path = sys.argv[1]

    if not os.path.exists(history_path):
        print(f"[!] History DB not found: {history_path}", file=sys.stderr)
        sys.exit(1)

    row = get_last_malicious_visit(history_path)
    if not row:
        print("[!] No suspicious website visit found.", file=sys.stderr)
        sys.exit(2)

    url, title, visit_time = row
    ts = chrome_us_to_utc_iso(int(visit_time))
    flag = f"CIT{{{ts}}}"

    print(f"URL       : {url}")
    print(f"Title     : {title}")
    print(f"VisitTime : {visit_time}")
    print(f"UTC       : {ts}")
    print(flag)


if __name__ == "__main__":
    main()
