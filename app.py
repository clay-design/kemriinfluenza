from flask import Flask, request, jsonify, render_template, session
import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'kemri_cghr_influenza_2026_strong_secret'
DB_PATH = 'kemri_influenza.db'
FACILITIES = ['Bondo', 'Siaya', 'Kuoyo', 'Lumumba']


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table_columns(conn, table_name, columns):
    c = conn.cursor()
    c.execute(f'PRAGMA table_info({table_name})')
    existing_columns = {row['name'] for row in c.fetchall()}
    for name, definition in columns.items():
        if name not in existing_columns:
            c.execute(f'ALTER TABLE {table_name} ADD COLUMN {name} {definition}')
    conn.commit()


def get_initials(name):
    parts = name.strip().split()
    if not parts:
        return ''
    return (parts[0][0] + (parts[-1][0] if len(parts) > 1 else '')).upper()


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        full_name TEXT,
        initials TEXT,
        role TEXT DEFAULT 'Field Technician',
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS screening (
        screening_id TEXT PRIMARY KEY,
        date TEXT,
        facility TEXT,
        dob TEXT,
        age_years INTEGER,
        age_months INTEGER,
        height REAL,
        weight REAL,
        temperature REAL,
        temp_method TEXT,
        resp_rate INTEGER,
        pulse_rate INTEGER,
        bp TEXT,
        lmp TEXT,
        fundal_height INTEGER,
        inc_resident TEXT,
        inc_pregnancy TEXT,
        inc_gestation TEXT,
        inc_hiv TEXT,
        inc_delivery TEXT,
        exc_multiple TEXT,
        exc_fistula TEXT,
        exc_mental TEXT,
        eligibility TEXT,
        consent TEXT,
        consent_reason TEXT,
        user_initials TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS enrolment (
        screening_id TEXT PRIMARY KEY,
        facility TEXT,
        dob TEXT,
        age_years INTEGER,
        age_months INTEGER,
        marital_status TEXT,
        husband_name TEXT,
        village TEXT,
        education TEXT,
        occupation TEXT,
        height REAL,
        weight REAL,
        temperature REAL,
        temp_method TEXT,
        resp_rate INTEGER,
        pulse_rate INTEGER,
        bp TEXT,
        estimated_ga TEXT,
        user_initials TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS delivery (
        screening_id TEXT PRIMARY KEY,
        date TEXT,
        mother_weight REAL,
        bmi TEXT,
        bmi_unknown TEXT,
        temperature REAL,
        temp_method TEXT,
        resp_rate INTEGER,
        pulse_rate INTEGER,
        bp TEXT,
        oxygen_saturation INTEGER,
        oxygen_support TEXT,
        abnormal_exam TEXT,
        abnormal_specify TEXT,
        delivery_date TEXT,
        delivery_time TEXT,
        delivery_location TEXT,
        delivery_location_other TEXT,
        delivery_provider TEXT,
        delivery_provider_other TEXT,
        mode TEXT,
        csection_indication TEXT,
        csection_indication_other TEXT,
        user_initials TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS closeout (
        screening_id TEXT PRIMARY KEY,
        date TEXT,
        termination_date TEXT,
        status TEXT,
        reason TEXT,
        user_initials TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS drafts (
        id INTEGER PRIMARY KEY,
        form_type TEXT,
        screening_id TEXT,
        user_name TEXT,
        draft_data TEXT,
        updated_at TEXT,
        UNIQUE(form_type, screening_id, user_name)
    )''')

    ensure_table_columns(conn, 'enrolment', {
        'facility': 'TEXT',
        'dob': 'TEXT',
        'age_years': 'INTEGER',
        'age_months': 'INTEGER',
        'marital_status': 'TEXT',
        'husband_name': 'TEXT',
        'village': 'TEXT',
        'education': 'TEXT',
        'occupation': 'TEXT',
        'height': 'REAL',
        'weight': 'REAL',
        'temperature': 'REAL',
        'temp_method': 'TEXT',
        'resp_rate': 'INTEGER',
        'pulse_rate': 'INTEGER',
        'bp': 'TEXT',
        'estimated_ga': 'TEXT'
    })
    ensure_table_columns(conn, 'delivery', {
        'date': 'TEXT',
        'mother_weight': 'REAL',
        'bmi': 'TEXT',
        'bmi_unknown': 'TEXT',
        'temperature': 'REAL',
        'temp_method': 'TEXT',
        'resp_rate': 'INTEGER',
        'pulse_rate': 'INTEGER',
        'bp': 'TEXT',
        'oxygen_saturation': 'INTEGER',
        'oxygen_support': 'TEXT',
        'abnormal_exam': 'TEXT',
        'abnormal_specify': 'TEXT',
        'delivery_date': 'TEXT',
        'delivery_time': 'TEXT',
        'delivery_location': 'TEXT',
        'delivery_location_other': 'TEXT',
        'delivery_provider': 'TEXT',
        'delivery_provider_other': 'TEXT',
        'mode': 'TEXT',
        'csection_indication': 'TEXT',
        'csection_indication_other': 'TEXT'
    })
    ensure_table_columns(conn, 'closeout', {
        'date': 'TEXT',
        'termination_date': 'TEXT',
        'status': 'TEXT',
        'reason': 'TEXT'
    })

    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        c.execute('INSERT INTO users (username, password_hash, full_name, initials, role, created_at) VALUES (?,?,?,?,?,?)',
                  ('admin', generate_password_hash('admin123'), 'Data Manager', get_initials('Data Manager'), 'Data Manager', datetime.now().isoformat()))
        c.execute('INSERT INTO users (username, password_hash, full_name, initials, role, created_at) VALUES (?,?,?,?,?,?)',
                  ('tech', generate_password_hash('tech123'), 'Field Technician', get_initials('Field Technician'), 'Field Technician', datetime.now().isoformat()))

    conn.commit()
    conn.close()


init_db()


@app.route('/')
def index():
    return render_template('index.html')


def require_login():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401


def require_manager():
    if session['user'].get('role') != 'Data Manager':
        return jsonify({'success': False, 'message': 'Forbidden: insufficient permissions'}), 403


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username, role, initials, full_name, password_hash FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['user'] = {
            'username': user['username'],
            'role': user['role'],
            'initials': user['initials'],
            'full_name': user['full_name']
        }
        return jsonify({'success': True, 'user': session['user']})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'success': True})


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    if not data.get('username') or not data.get('password') or not data.get('full_name'):
        return jsonify({'success': False, 'message': 'username, password and full_name are required'}), 400

    username = data['username'].strip()
    full_name = data['full_name'].strip()
    role = data.get('role', 'Field Technician')
    if role not in ['Field Technician', 'Data Manager']:
        return jsonify({'success': False, 'message': 'Invalid role selected.'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as count FROM users WHERE role='Data Manager'")
    manager_count = c.fetchone()['count']

    # Allow first Data Manager to be created without authentication
    # After that, only logged-in Data Managers can create new ones
    if role == 'Data Manager':
        if manager_count > 0 and ('user' not in session or session['user'].get('role') != 'Data Manager'):
            conn.close()
            return jsonify({'success': False, 'message': 'Only an existing Data Manager can create new Data Manager accounts'}), 403
    else:
        # Field Technicians can always self-register
        if 'user' in session and session['user'].get('role') != 'Data Manager':
            conn.close()
            return jsonify({'success': False, 'message': 'Only a Data Manager can create users while logged in'}), 403

    password_hash = generate_password_hash(data['password'])
    initials = get_initials(full_name)

    try:
        c.execute('INSERT INTO users (username, password_hash, full_name, initials, role, created_at) VALUES (?,?,?,?,?,?)',
                  (username, password_hash, full_name, initials, role, datetime.now().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Username already exists'}), 409
    conn.close()
    return jsonify({'success': True, 'message': 'Account created successfully'})


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')

    if not username or not old_password or not new_password:
        return jsonify({'success': False, 'message': 'username, old_password and new_password are required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    user = c.fetchone()
    if not user or not check_password_hash(user['password_hash'], old_password):
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid username or old password'}), 401

    password_hash = generate_password_hash(new_password)
    c.execute('UPDATE users SET password_hash=? WHERE username=?', (password_hash, username))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Password changed successfully. Please login with your new password.'})


@app.route('/api/users')
def list_users():
    auth = require_login()
    if auth:
        return auth
    authz = require_manager()
    if authz:
        return authz

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username, full_name, initials, role, created_at FROM users ORDER BY role DESC, username')
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)


@app.route('/api/users/<username>/reset-password', methods=['POST'])
def admin_reset_user_password(username):
    auth = require_login()
    if auth:
        return auth
    authz = require_manager()
    if authz:
        return authz

    data = request.get_json() or {}
    new_password = data.get('new_password', '')
    if not new_password:
        return jsonify({'success': False, 'message': 'new_password is required'}), 400

    password_hash = generate_password_hash(new_password)
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username=?', (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404

    c.execute('UPDATE users SET password_hash=? WHERE username=?', (password_hash, username))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Password updated for {username}.'})


def renumber_screening_ids(conn):
    c = conn.cursor()
    c.execute('SELECT screening_id FROM screening ORDER BY screening_id')
    rows = [row['screening_id'] for row in c.fetchall()]
    mapping = {}
    for index, screening_id in enumerate(rows, start=1):
        new_id = f"SCR-{index:04d}"
        if screening_id != new_id:
            mapping[screening_id] = new_id
    if not mapping:
        return

    for old_id, new_id in mapping.items():
        temp_id = f"__TMP__{old_id}"
        c.execute('UPDATE screening SET screening_id=? WHERE screening_id=?', (temp_id, old_id))
        c.execute('UPDATE enrolment SET screening_id=? WHERE screening_id=?', (temp_id, old_id))
        c.execute('UPDATE delivery SET screening_id=? WHERE screening_id=?', (temp_id, old_id))
        c.execute('UPDATE closeout SET screening_id=? WHERE screening_id=?', (temp_id, old_id))
        c.execute('UPDATE drafts SET screening_id=? WHERE screening_id=?', (temp_id, old_id))
    conn.commit()

    for old_id, new_id in mapping.items():
        temp_id = f"__TMP__{old_id}"
        c.execute('UPDATE screening SET screening_id=? WHERE screening_id=?', (new_id, temp_id))
        c.execute('UPDATE enrolment SET screening_id=? WHERE screening_id=?', (new_id, temp_id))
        c.execute('UPDATE delivery SET screening_id=? WHERE screening_id=?', (new_id, temp_id))
        c.execute('UPDATE closeout SET screening_id=? WHERE screening_id=?', (new_id, temp_id))
        c.execute('UPDATE drafts SET screening_id=? WHERE screening_id=?', (new_id, temp_id))
    conn.commit()


def delete_screenings(conn, ids):
    c = conn.cursor()
    for screening_id in ids:
        c.execute('DELETE FROM screening WHERE screening_id=?', (screening_id,))
        c.execute('DELETE FROM enrolment WHERE screening_id=?', (screening_id,))
        c.execute('DELETE FROM delivery WHERE screening_id=?', (screening_id,))
        c.execute('DELETE FROM closeout WHERE screening_id=?', (screening_id,))
        c.execute('DELETE FROM drafts WHERE screening_id=?', (screening_id,))
    conn.commit()


@app.route('/api/drafts/<form_type>/<screening_id>')
def get_draft(form_type, screening_id):
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT draft_data FROM drafts WHERE form_type=? AND screening_id=? AND user_name=?',
              (form_type, screening_id, session['user']['username']))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({})
    try:
        return jsonify(json.loads(row['draft_data']))
    except Exception:
        return jsonify({})


@app.route('/api/drafts/<form_type>/<screening_id>', methods=['POST'])
def save_draft(form_type, screening_id):
    auth = require_login()
    if auth:
        return auth

    data = request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'success': False, 'message': 'Draft data must be an object.'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO drafts (form_type, screening_id, user_name, draft_data, updated_at) VALUES (?,?,?,?,?)',
              (form_type, screening_id, session['user']['username'], json.dumps(data), datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/drafts/<form_type>/<screening_id>', methods=['DELETE'])
def delete_draft(form_type, screening_id):
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM drafts WHERE form_type=? AND screening_id=? AND user_name=?',
              (form_type, screening_id, session['user']['username']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/screenings/delete', methods=['POST'])
def delete_multiple_screenings():
    auth = require_login()
    if auth:
        return auth
    authz = require_manager()
    if authz:
        return authz

    data = request.get_json() or {}
    screening_ids = data.get('screening_ids')
    if not isinstance(screening_ids, list) or not screening_ids:
        return jsonify({'success': False, 'message': 'screening_ids must be a non-empty list'}), 400

    conn = get_db()
    delete_screenings(conn, screening_ids)
    renumber_screening_ids(conn)
    conn.close()

    return jsonify({'success': True, 'message': f'Deleted {len(screening_ids)} screening(s) and renumbered remaining records.'})


@app.route('/api/screenings/delete-all', methods=['POST'])
def delete_all_screenings():
    auth = require_login()
    if auth:
        return auth
    authz = require_manager()
    if authz:
        return authz

    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM screening')
    c.execute('DELETE FROM enrolment')
    c.execute('DELETE FROM delivery')
    c.execute('DELETE FROM closeout')
    c.execute('DELETE FROM drafts')
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'All screening records have been deleted.'})


@app.route('/api/screenings/<screening_id>', methods=['DELETE'])
def delete_screening(screening_id):
    auth = require_login()
    if auth:
        return auth
    authz = require_manager()
    if authz:
        return authz

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT screening_id FROM screening WHERE screening_id=?', (screening_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Screening ID not found'}), 404

    c.execute('DELETE FROM screening WHERE screening_id=?', (screening_id,))
    c.execute('DELETE FROM enrolment WHERE screening_id=?', (screening_id,))
    c.execute('DELETE FROM delivery WHERE screening_id=?', (screening_id,))
    c.execute('DELETE FROM closeout WHERE screening_id=?', (screening_id,))
    c.execute('DELETE FROM drafts WHERE screening_id=?', (screening_id,))
    renumber_screening_ids(conn)
    conn.close()

    return jsonify({'success': True, 'message': f'Screening {screening_id} deleted and remaining IDs renumbered.'})


@app.route('/api/screening', methods=['POST'])
def save_screening():
    auth = require_login()
    if auth:
        return auth

    d = request.get_json() or {}
    if not d.get('screening_id'):
        return jsonify({'success': False, 'message': 'Screening ID is required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO screening (
        screening_id, date, facility, dob, age_years, age_months,
        height, weight, temperature, temp_method, resp_rate, pulse_rate,
        bp, lmp, fundal_height, inc_resident, inc_pregnancy, inc_gestation,
        inc_hiv, inc_delivery, exc_multiple, exc_fistula, exc_mental,
        eligibility, consent, consent_reason, user_initials, timestamp
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        d['screening_id'], d.get('date'), d.get('facility'), d.get('dob'), d.get('age_years'), d.get('age_months'),
        d.get('height'), d.get('weight'), d.get('temperature'), d.get('temp_method'), d.get('resp_rate'), d.get('pulse_rate'),
        d.get('bp'), d.get('lmp'), d.get('fundal_height'), d.get('inc_resident'), d.get('inc_pregnancy'), d.get('inc_gestation'),
        d.get('inc_hiv'), d.get('inc_delivery'), d.get('exc_multiple'), d.get('exc_fistula'), d.get('exc_mental'),
        d.get('eligibility'), d.get('consent'), d.get('consent_reason'), session['user']['initials'], datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/enrolment', methods=['POST'])
def save_enrolment():
    auth = require_login()
    if auth:
        return auth

    d = request.get_json() or {}
    if not d.get('screening_id'):
        return jsonify({'success': False, 'message': 'Screening ID is required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT eligibility, consent FROM screening WHERE screening_id=?', (d['screening_id'],))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Screening ID not found'}), 400
    if row['eligibility'] != 'Yes' or row['consent'] != 'Yes':
        conn.close()
        return jsonify({'success': False, 'message': 'Subject is not eligible for enrolment'}), 400

    required_fields = ['facility', 'dob', 'marital_status', 'village', 'education', 'occupation', 'temp_method', 'bp']
    missing_fields = [field for field in required_fields if not d.get(field)]
    if missing_fields:
        conn.close()
        return jsonify({'success': False, 'message': f'Missing enrolment fields: {", ".join(missing_fields)}'}), 400

    c.execute('''INSERT OR REPLACE INTO enrolment (
        screening_id, facility, dob, age_years, age_months, marital_status,
        husband_name, village, education, occupation, height, weight,
        temperature, temp_method, resp_rate, pulse_rate, bp, estimated_ga,
        user_initials, timestamp
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        d['screening_id'], d.get('facility'), d.get('dob'), d.get('age_years'), d.get('age_months'),
        d.get('marital_status'), d.get('husband_name'), d.get('village'), d.get('education'), d.get('occupation'),
        d.get('height'), d.get('weight'), d.get('temperature'), d.get('temp_method'), d.get('resp_rate'),
        d.get('pulse_rate'), d.get('bp'), d.get('estimated_ga'), session['user']['initials'], datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/delivery', methods=['POST'])
def save_delivery():
    auth = require_login()
    if auth:
        return auth

    d = request.get_json() or {}
    if not d.get('screening_id'):
        return jsonify({'success': False, 'message': 'Screening ID is required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT screening_id FROM enrolment WHERE screening_id=?', (d['screening_id'],))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Enrolment record not found for this Screening ID'}), 400

    if not d.get('date') or not d.get('delivery_date') or not d.get('delivery_time'):
        conn.close()
        return jsonify({'success': False, 'message': 'Delivery date, time, and interview date are required.'}), 400

    if not d.get('delivery_location'):
        conn.close()
        return jsonify({'success': False, 'message': 'Delivery location is required.'}), 400
    if d['delivery_location'] in ['Other hospital/clinic', 'Other location'] and not d.get('delivery_location_other'):
        conn.close()
        return jsonify({'success': False, 'message': 'Please specify the other delivery location.'}), 400

    if not d.get('delivery_provider'):
        conn.close()
        return jsonify({'success': False, 'message': 'Delivery provider is required.'}), 400
    if d['delivery_provider'] == 'Other' and not d.get('delivery_provider_other'):
        conn.close()
        return jsonify({'success': False, 'message': 'Please specify the other delivery provider.'}), 400

    if not d.get('mode'):
        conn.close()
        return jsonify({'success': False, 'message': 'Mode of delivery is required.'}), 400
    if d['mode'] == 'C-section':
        if not d.get('csection_indication'):
            conn.close()
            return jsonify({'success': False, 'message': 'C-section indication is required.'}), 400
        if d['csection_indication'] == 'Other' and not d.get('csection_indication_other'):
            conn.close()
            return jsonify({'success': False, 'message': 'Please specify the other C-section indication.'}), 400

    if d.get('abnormal_exam') == 'Yes' and not d.get('abnormal_specify'):
        conn.close()
        return jsonify({'success': False, 'message': 'Please specify the abnormal exam findings.'}), 400

    c.execute('''INSERT OR REPLACE INTO delivery (
        screening_id, date, mother_weight, bmi, bmi_unknown, temperature, temp_method, resp_rate,
        pulse_rate, bp, oxygen_saturation, oxygen_support, abnormal_exam, abnormal_specify,
        delivery_date, delivery_time, delivery_location, delivery_location_other,
        delivery_provider, delivery_provider_other, mode, csection_indication,
        csection_indication_other, user_initials, timestamp
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        d['screening_id'], d.get('date'), d.get('mother_weight'), d.get('bmi'), d.get('bmi_unknown'),
        d.get('temperature'), d.get('temp_method'), d.get('resp_rate'), d.get('pulse_rate'), d.get('bp'),
        d.get('oxygen_saturation'), d.get('oxygen_support'), d.get('abnormal_exam'), d.get('abnormal_specify'),
        d.get('delivery_date'), d.get('delivery_time'), d.get('delivery_location'), d.get('delivery_location_other'),
        d.get('delivery_provider'), d.get('delivery_provider_other'), d.get('mode'), d.get('csection_indication'),
        d.get('csection_indication_other'), session['user']['initials'], datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/closeout', methods=['POST'])
def save_closeout():
    auth = require_login()
    if auth:
        return auth

    d = request.get_json() or {}
    if not d.get('screening_id'):
        return jsonify({'success': False, 'message': 'Screening ID is required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO closeout (
        screening_id, date, termination_date, status, reason, user_initials, timestamp
    ) VALUES (?,?,?,?,?,?,?)''', (
        d['screening_id'], d.get('date'), d.get('termination_date'), d.get('status'), d.get('reason'),
        session['user']['initials'], datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/eligible')
def get_eligible():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT screening_id FROM screening WHERE eligibility='Yes' AND consent='Yes'")
    ids = [row['screening_id'] for row in c.fetchall()]
    conn.close()
    return jsonify(ids)


@app.route('/api/enrolled')
def get_enrolled():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT screening_id FROM enrolment')
    ids = [row['screening_id'] for row in c.fetchall()]
    conn.close()
    return jsonify(ids)


@app.route('/api/screenings')
def list_screenings():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT screening_id, facility, dob, eligibility, consent FROM screening ORDER BY screening_id')
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route('/api/screening/<screening_id>')
def get_screening(screening_id):
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM screening WHERE screening_id=?', (screening_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'message': 'Screening not found'}), 404
    return jsonify(dict(row))


@app.route('/api/enrolment/<screening_id>')
def get_enrolment(screening_id):
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM enrolment WHERE screening_id=?', (screening_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({})
    return jsonify(dict(row))


@app.route('/api/delivery/<screening_id>')
def get_delivery(screening_id):
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM delivery WHERE screening_id=?', (screening_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({})
    return jsonify(dict(row))


@app.route('/api/stats')
def stats():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) as count FROM screening')
    screened = c.fetchone()['count']
    c.execute('SELECT COUNT(*) as count FROM enrolment')
    enrolled = c.fetchone()['count']
    c.execute('SELECT COUNT(*) as count FROM delivery')
    delivered = c.fetchone()['count']
    c.execute('SELECT COUNT(*) as count FROM closeout')
    closed = c.fetchone()['count']

    c.execute('''
        SELECT s.facility AS facility,
               COUNT(DISTINCT s.screening_id) AS screened,
               COUNT(DISTINCT e.screening_id) AS enrolled,
               COUNT(DISTINCT d.screening_id) AS delivered,
               COUNT(DISTINCT c.screening_id) AS closed
        FROM screening s
        LEFT JOIN enrolment e ON s.screening_id = e.screening_id
        LEFT JOIN delivery d ON s.screening_id = d.screening_id
        LEFT JOIN closeout c ON s.screening_id = c.screening_id
        GROUP BY s.facility
    ''')
    sites = [dict(row) for row in c.fetchall()]
    conn.close()

    return jsonify({
        'screened': screened,
        'enrolled': enrolled,
        'delivered': delivered,
        'closed': closed,
        'sites': sites
    })


if __name__ == '__main__':
    import socket

    def find_free_port(preferred=5000, host='127.0.0.1'):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, preferred))
                return preferred
            except OSError:
                sock.bind((host, 0))
                return sock.getsockname()[1]

    port = find_free_port()
    print(f"Starting Flask on http://127.0.0.1:{port}")
    app.run(debug=True, port=port)
