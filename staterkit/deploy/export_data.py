"""Export local SQLite data to PostgreSQL-compatible SQL file."""
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'cuba.db')
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seed_data.sql')

# Tables in dependency order (foreign keys)
TABLES = [
    'company',
    'user',
    'watchlist_entry',
    'audit_log',
    'notification',
    'user_activity',
    'alert_rule',
    'scheduled_report',
    'report_history',
    'breached_cred_meta',
]

def escape_sql(val):
    if val is None:
        return 'NULL'
    if isinstance(val, bool):
        return 'TRUE' if val else 'FALSE'
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("'", "''")
    return f"'{s}'"

def export():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    lines = []
    lines.append('-- D-SECLAB Data Export from SQLite')
    lines.append(f'-- Generated: {datetime.now().isoformat()}')
    lines.append('')
    lines.append('BEGIN;')
    lines.append('')

    for table in TABLES:
        try:
            cur.execute(f'SELECT * FROM "{table}"')
        except sqlite3.OperationalError:
            print(f'  Skipping {table} (not found)')
            continue

        rows = cur.fetchall()
        if not rows:
            print(f'  {table}: 0 rows (skipped)')
            continue

        cols = [desc[0] for desc in cur.description]
        col_names = ', '.join(f'"{c}"' for c in cols)

        lines.append(f'-- {table} ({len(rows)} rows)')
        for row in rows:
            vals = ', '.join(escape_sql(row[c]) for c in cols)
            lines.append(f'INSERT INTO "{table}" ({col_names}) VALUES ({vals}) ON CONFLICT DO NOTHING;')
        lines.append('')

        # Reset sequence for tables with id column
        if 'id' in cols:
            lines.append(f"SELECT setval(pg_get_serial_sequence('\"{table}\"', 'id'), COALESCE(MAX(id), 1)) FROM \"{table}\";")
            lines.append('')

        print(f'  {table}: {len(rows)} rows')

    lines.append('COMMIT;')
    lines.append('')

    with open(OUTPUT, 'w') as f:
        f.write('\n'.join(lines))

    print(f'\nExported to: {OUTPUT}')

if __name__ == '__main__':
    export()
