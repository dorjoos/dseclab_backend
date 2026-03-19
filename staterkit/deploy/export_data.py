"""Export local SQLite data to PostgreSQL-compatible SQL file."""
import sqlite3
import os
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

# Only export these columns per table (must match PostgreSQL model)
TABLE_COLUMNS = {
    'company': ['id', 'name', 'domain', 'company_type', 'description', 'created_at', 'updated_at'],
    'user': ['id', 'username', 'email', 'password', 'role', 'isAdmin', 'company_id', 'is_active', 'last_login', 'created_at', 'updated_at', 'totp_secret', 'totp_enabled', 'permissions'],
    'watchlist_entry': ['id', 'company_id', 'entry_type', 'entry_value', 'description', 'created_at', 'updated_at'],
    'audit_log': ['id', 'user_id', 'action_type', 'resource_type', 'resource_id', 'description', 'ip_address', 'user_agent', 'old_values', 'new_values', 'status', 'error_message', 'created_at'],
    'notification': ['id', 'user_id', 'notification_type', 'title', 'message', 'link', 'is_read', 'read_at', 'created_at'],
    'user_activity': ['id', 'user_id', 'activity_type', 'ip_address', 'user_agent', 'location', 'status', 'failure_reason', 'created_at'],
    'alert_rule': ['id', 'name', 'condition_type', 'condition_value', 'notify_method', 'notify_target', 'is_active', 'trigger_count', 'last_triggered', 'created_by', 'created_at'],
    'scheduled_report': ['id', 'name', 'frequency', 'format', 'filters', 'email_to', 'is_active', 'last_run', 'next_run', 'created_by', 'created_at'],
    'report_history': ['id', 'name', 'format', 'file_size', 'record_count', 'status', 'source', 'schedule_id', 'generated_by', 'created_at'],
    'breached_cred_meta': ['id', 'es_id', 'is_marked', 'marked_by', 'marked_at', 'notes', 'created_at'],
}

BOOL_COLUMNS = {'isAdmin', 'is_active', 'totp_enabled', 'is_read', 'is_marked'}


def escape_sql(val, col_name=None):
    if val is None:
        return 'NULL'
    if col_name and col_name in BOOL_COLUMNS:
        return 'TRUE' if val else 'FALSE'
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

        # Use only columns that exist in the model
        allowed = TABLE_COLUMNS.get(table)
        all_cols = [desc[0] for desc in cur.description]
        cols = [c for c in all_cols if c in allowed] if allowed else all_cols

        col_names = ', '.join(f'"{c}"' for c in cols)

        lines.append(f'-- {table} ({len(rows)} rows)')
        for row in rows:
            vals = ', '.join(escape_sql(row[c], c) for c in cols)
            lines.append(f'INSERT INTO "{table}" ({col_names}) VALUES ({vals}) ON CONFLICT DO NOTHING;')
        lines.append('')

        # Reset sequence
        if 'id' in cols:
            lines.append(f"SELECT setval(pg_get_serial_sequence('\"{table}\"', 'id'), COALESCE(MAX(id), 1)) FROM \"{table}\";")
            lines.append('')

        print(f'  {table}: {len(rows)} rows ({len(cols)} cols)')

    lines.append('')

    with open(OUTPUT, 'w') as f:
        f.write('\n'.join(lines))

    print(f'\nExported to: {OUTPUT}')


if __name__ == '__main__':
    export()
