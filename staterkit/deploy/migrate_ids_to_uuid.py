"""Convert integer IDs to UUIDs in seed_data.sql while preserving all data and foreign key relationships."""
import uuid
import re
import os

INPUT = '/tmp/old_seed_data.sql'
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seed_data.sql')

# ID maps: table -> {old_int_id -> new_uuid}
id_maps = {
    'company': {},
    'user': {},
    'watchlist_entry': {},
    'audit_log': {},
    'notification': {},
    'user_activity': {},
    'alert_rule': {},
    'scheduled_report': {},
    'report_history': {},
    'breached_cred_meta': {},
}

# Foreign key columns -> which table's ID map to use
FK_MAP = {
    'company_id': 'company',
    'user_id': 'user',
    'marked_by': 'user',
    'created_by': 'user',
    'generated_by': 'user',
    'schedule_id': 'scheduled_report',
    'resource_id': None,  # polymorphic - needs special handling
}

BOOL_COLUMNS = {'isAdmin', 'is_active', 'totp_enabled', 'is_read', 'is_marked'}


def get_uuid(table, old_id):
    """Get or create a UUID for an old integer ID."""
    if old_id is None or old_id == 'NULL':
        return None
    old_id = str(old_id)
    if old_id not in id_maps[table]:
        id_maps[table][old_id] = str(uuid.uuid4())
    return id_maps[table][old_id]


def parse_insert(line):
    """Parse an INSERT INTO statement and return (table, columns, values_str)."""
    m = re.match(r'INSERT INTO "(\w+)" \((.+?)\) VALUES \((.+)\) ON CONFLICT DO NOTHING;', line)
    if not m:
        return None, None, None
    table = m.group(1)
    cols_str = m.group(2)
    vals_str = m.group(3)

    cols = [c.strip().strip('"') for c in cols_str.split(',')]
    return table, cols, vals_str


def parse_values(vals_str):
    """Parse SQL values string into list of values, handling quoted strings."""
    values = []
    i = 0
    current = ''
    in_quote = False

    while i < len(vals_str):
        c = vals_str[i]
        if c == "'" and not in_quote:
            in_quote = True
            current += c
        elif c == "'" and in_quote:
            # Check for escaped quote ''
            if i + 1 < len(vals_str) and vals_str[i + 1] == "'":
                current += "''"
                i += 2
                continue
            else:
                in_quote = False
                current += c
        elif c == ',' and not in_quote:
            values.append(current.strip())
            current = ''
        else:
            current += c
        i += 1

    if current.strip():
        values.append(current.strip())

    return values


def convert():
    with open(INPUT, 'r') as f:
        lines = f.readlines()

    # First pass: assign UUIDs to all primary keys
    for line in lines:
        line = line.strip()
        table, cols, vals_str = parse_insert(line)
        if not table or 'id' not in cols:
            continue
        vals = parse_values(vals_str)
        id_idx = cols.index('id')
        old_id = vals[id_idx].strip("'")
        get_uuid(table, old_id)

    # Second pass: rewrite all lines with UUIDs
    output_lines = []
    for line in lines:
        line = line.rstrip()

        # Skip setval lines (no sequences with UUIDs)
        if line.strip().startswith('SELECT setval'):
            continue
        # Skip BEGIN/COMMIT
        if line.strip() in ('BEGIN;', 'COMMIT;'):
            continue

        table, cols, vals_str = parse_insert(line)
        if not table:
            output_lines.append(line)
            continue

        vals = parse_values(vals_str)

        new_vals = []
        for i, (col, val) in enumerate(zip(cols, vals)):
            if col == 'id':
                old_id = val.strip("'")
                new_uuid = get_uuid(table, old_id)
                new_vals.append(f"'{new_uuid}'")
            elif col in FK_MAP and FK_MAP[col] is not None:
                if val == 'NULL':
                    new_vals.append('NULL')
                else:
                    old_fk = val.strip("'")
                    fk_table = FK_MAP[col]
                    new_uuid = get_uuid(fk_table, old_fk)
                    new_vals.append(f"'{new_uuid}'" if new_uuid else 'NULL')
            elif col == 'resource_id':
                # resource_id is polymorphic - try to map based on resource_type
                if val == 'NULL':
                    new_vals.append('NULL')
                else:
                    # Get resource_type from same row
                    rt_idx = cols.index('resource_type') if 'resource_type' in cols else -1
                    if rt_idx >= 0:
                        rt = vals[rt_idx].strip("'")
                        if rt in id_maps:
                            old_fk = val.strip("'")
                            new_uuid = get_uuid(rt, old_fk)
                            new_vals.append(f"'{new_uuid}'" if new_uuid else val)
                        else:
                            new_vals.append(val)
                    else:
                        new_vals.append(val)
            elif col in BOOL_COLUMNS:
                # Convert 0/1 to TRUE/FALSE
                if val in ('0', 'FALSE', 'false'):
                    new_vals.append('FALSE')
                elif val in ('1', 'TRUE', 'true'):
                    new_vals.append('TRUE')
                else:
                    new_vals.append(val)
            else:
                new_vals.append(val)

        col_names = ', '.join(f'"{c}"' for c in cols)
        vals_joined = ', '.join(new_vals)
        output_lines.append(f'INSERT INTO "{table}" ({col_names}) VALUES ({vals_joined}) ON CONFLICT DO NOTHING;')

    with open(OUTPUT, 'w') as f:
        f.write('\n'.join(output_lines) + '\n')

    print('ID mappings:')
    for table, mapping in id_maps.items():
        if mapping:
            print(f'  {table}: {len(mapping)} IDs converted')
    print(f'\nOutput: {OUTPUT}')


if __name__ == '__main__':
    convert()
