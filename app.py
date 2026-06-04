import os, json, bcrypt, jwt, base64, io, math
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from supabase import create_client

app = Flask(__name__, static_folder='static')
CORS(app)

SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
JWT_SECRET   = os.environ.get('JWT_SECRET', 'dialer-secret-2024')

sb = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── AUTH ──────────────────────────────────────────────────
def make_token(user):
    payload = {
        'id':    user['id'],
        'email': user['email'],
        'role':  user['role'],
        'name':  user.get('name',''),
        'exp':   datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token():
    auth = request.headers.get('Authorization','')
    if not auth.startswith('Bearer '): return None
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=['HS256'])
    except:
        return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = verify_token()
        if not user: return jsonify({'error':'Giriş gerekli'}), 401
        request.user = user
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = verify_token()
        if not user: return jsonify({'error':'Giriş gerekli'}), 401
        if user.get('role') != 'admin': return jsonify({'error':'Yetkisiz'}), 403
        request.user = user
        return f(*args, **kwargs)
    return wrapper

# ── XLSX PARSE ───────────────────────────────────────────
@app.route('/api/xlsx/parse', methods=['POST'])
@require_auth
def parse_xlsx():
    try:
        import pandas as pd
        data = request.json
        b64  = data.get('data', '')
        raw  = base64.b64decode(b64)
        xl   = pd.ExcelFile(io.BytesIO(raw))
        # Bos sayfalari filtrele
        valid = [s for s in xl.sheet_names if not s.strip().lower().startswith('sayfa') or not s[5:].strip().isdigit()]
        sheets_info = {}
        for sheet in valid:
            df = pd.read_excel(io.BytesIO(raw), sheet_name=sheet, header=1)
            # Tel No kolonunu bul
            tel_col = next((c for c in df.columns if 'tel' in str(c).lower()), None)
            if tel_col:
                df = df[df[tel_col].notna()].copy()
                # Sadece sayisal telefon numarasi icerenleri al (Data Raporu satirlarini ele)
                def is_valid_tel(x):
                    try: return len(str(int(float(x)))) >= 7
                    except: return False
                df = df[df[tel_col].apply(is_valid_tel)].copy()
                df[tel_col] = df[tel_col].apply(lambda x: str(int(float(x))) if pd.notna(x) else '')
            df = df.where(pd.notna(df), None)
            rows = []
            for i, (_, row) in enumerate(df.iterrows()):
                r = {'_row': i+1}
                for col in df.columns:
                    if not str(col).startswith('Unnamed'):
                        val = row[col]
                        if isinstance(val, float) and math.isnan(val):
                            r[str(col)] = None
                        else:
                            r[str(col)] = str(val) if val is not None else None
                rows.append(r)
            sheets_info[sheet] = {
                'columns': [c for c in df.columns if not str(c).startswith('Unnamed')],
                'rows': rows,
                'count': len(rows)
            }
        return jsonify({'sheets': valid, 'data': sheets_info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── STATIC ────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# ── AUTH ROUTES ───────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email','').lower().strip()
    password = data.get('password','')
    res = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error':'Email veya sifre hatali'}), 401
    user = res.data[0]
    stored = user['password']
    try:
        ok = bcrypt.checkpw(password.encode(), stored.encode())
    except Exception:
        ok = (password == stored)
    if not ok:
        return jsonify({'error':'Email veya sifre hatali'}), 401
    token = make_token(user)
    return jsonify({'token': token, 'user': {
        'id': user['id'], 'email': user['email'],
        'name': user.get('name',''), 'role': user['role']
    }})

@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    return jsonify(request.user)

# ── USERS (admin) ─────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@require_admin
def get_users():
    res = sb.table('users').select('id,email,name,role,created_at').execute()
    return jsonify(res.data)

@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    data = request.json
    email = data.get('email','').lower().strip()
    password = data.get('password','')
    name = data.get('name','')
    role = data.get('role','user')
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    res = sb.table('users').insert({
        'email': email, 'password': hashed,
        'name': name, 'role': role
    }).execute()
    return jsonify(res.data[0])

@app.route('/api/users/<uid>', methods=['DELETE'])
@require_admin
def delete_user(uid):
    sb.table('users').delete().eq('id', uid).execute()
    return jsonify({'ok': True})

@app.route('/api/users/<uid>/password', methods=['PUT'])
@require_admin
def change_password(uid):
    data = request.json
    hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    sb.table('users').update({'password': hashed}).eq('id', uid).execute()
    return jsonify({'ok': True})

# ── LISTS ─────────────────────────────────────────────────
@app.route('/api/lists', methods=['GET'])
@require_auth
def get_lists():
    user = request.user
    if user['role'] == 'admin':
        res = sb.table('data_lists').select('*,users!assigned_to(name,email)').order('created_at', desc=True).execute()
    else:
        res = sb.table('data_lists').select('*').eq('assigned_to', user['id']).order('created_at', desc=True).execute()
    return jsonify(res.data)

@app.route('/api/lists', methods=['POST'])
@require_auth
def create_list():
    data = request.json
    res = sb.table('data_lists').insert({
        'name': data['name'],
        'sheet': data.get('sheet',''),
        'assigned_to': data.get('assigned_to'),
        'created_by': request.user['id'],
        'gs_url': data.get('gs_url','')
    }).execute()
    return jsonify(res.data[0])

@app.route('/api/lists/<lid>/gsurl', methods=['PUT'])
@require_admin
def update_list_gsurl(lid):
    data = request.json
    sb.table('data_lists').update({'gs_url': data.get('gs_url','')}).eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>', methods=['DELETE'])
@require_admin
def delete_list(lid):
    sb.table('data_lists').delete().eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>/assign', methods=['PUT'])
@require_admin
def assign_list(lid):
    data = request.json
    sb.table('data_lists').update({'assigned_to': data['user_id']}).eq('id', lid).execute()
    return jsonify({'ok': True})

# ── CONTACTS ──────────────────────────────────────────────
@app.route('/api/lists/<lid>/contacts', methods=['GET'])
@require_auth
def get_contacts(lid):
    user = request.user
    # Yetki kontrol
    if user['role'] != 'admin':
        lst = sb.table('data_lists').select('assigned_to').eq('id', lid).execute()
        if not lst.data or lst.data[0]['assigned_to'] != user['id']:
            return jsonify({'error':'Yetkisiz'}), 403
    res = sb.table('contacts').select('*').eq('list_id', lid).order('row_index').execute()
    return jsonify(res.data)

@app.route('/api/lists/<lid>/contacts', methods=['POST'])
@require_auth
def upload_contacts(lid):
    data = request.json
    rows = data.get('rows', [])
    # Onceki kisiileri sil
    sb.table('contacts').delete().eq('list_id', lid).execute()
    # Toplu ekle
    batch = []
    for i, r in enumerate(rows):
        batch.append({
            'list_id': lid,
            'row_index': i + 1,
            'name': r.get('name',''),
            'tel': r.get('tel',''),
            'extra': r.get('extra', {}),
            'sonuc': r.get('sonuc'),
            'not_text': r.get('not_text','')
        })
        if len(batch) >= 500:
            sb.table('contacts').insert(batch).execute()
            batch = []
    if batch:
        sb.table('contacts').insert(batch).execute()
    return jsonify({'ok': True, 'count': len(rows)})

@app.route('/api/contacts/<cid>/result', methods=['PUT'])
@require_auth
def update_result(cid):
    data = request.json
    update = {'updated_at': datetime.utcnow().isoformat()}
    if 'sonuc' in data:    update['sonuc']    = data['sonuc']
    if 'donus' in data:    update['donus']    = data['donus']
    if 'not_text' in data: update['not_text'] = data['not_text']
    sb.table('contacts').update(update).eq('id', cid).execute()
    sb.table('results').insert({
        'contact_id': cid,
        'user_id': request.user['id'],
        'sonuc': data.get('sonuc'),
        'not_text': data.get('not_text','')
    }).execute()
    return jsonify({'ok': True})

# ── STATS (admin) ─────────────────────────────────────────
@app.route('/api/stats', methods=['GET'])
@require_admin
def get_stats():
    lists = sb.table('data_lists').select('id,name,assigned_to,users!assigned_to(name)').execute()
    result = []
    for lst in lists.data:
        contacts = sb.table('contacts').select('id,sonuc').eq('list_id', lst['id']).execute()
        total = len(contacts.data)
        done  = len([c for c in contacts.data if c['sonuc']])
        sonuc_counts = {}
        for c in contacts.data:
            if c['sonuc']:
                sonuc_counts[c['sonuc']] = sonuc_counts.get(c['sonuc'], 0) + 1
        result.append({
            'list_id': lst['id'],
            'list_name': lst['name'],
            'assigned_to': lst.get('users', {}).get('name','') if lst.get('users') else '',
            'total': total,
            'done': done,
            'pct': round(done/total*100) if total else 0,
            'sonuc_counts': sonuc_counts
        })
    return jsonify(result)

# ── SETTINGS ──────────────────────────────────────────────
@app.route('/api/settings', methods=['GET', 'PUT'])
@require_auth
def settings():
    if request.method == 'GET':
        res = sb.table('settings').select('*').limit(1).execute()
        if res.data: return jsonify(res.data[0])
        return jsonify({'timeout_sec': 25, 'delay_between_calls': 10, 'gs_url': ''})
    if request.user['role'] != 'admin':
        return jsonify({'error':'Yetkisiz'}), 403
    data = request.json
    existing = sb.table('settings').select('id').limit(1).execute()
    if existing.data:
        sb.table('settings').update(data).eq('id', existing.data[0]['id']).execute()
    else:
        sb.table('settings').insert(data).execute()
    return jsonify({'ok': True})

# ── GOOGLE SHEETS PROXY ───────────────────────────────────
@app.route('/api/sheets/send', methods=['POST'])
@require_auth
def sheets_send():
    try:
        import requests as req_lib
        data = request.json
        # Önce list'e özel gs_url bak, yoksa global settings'ten al
        list_id = data.get('list_id')
        gs_url = ''
        if list_id:
            list_res = sb.table('data_lists').select('gs_url').eq('id', list_id).execute()
            if list_res.data: gs_url = list_res.data[0].get('gs_url','')
        if not gs_url:
            settings_res = sb.table('settings').select('gs_url').limit(1).execute()
            if settings_res.data: gs_url = settings_res.data[0].get('gs_url','')
        if not gs_url:
            return jsonify({'error': 'Google Sheets URL ayarlanmamış'}), 400
        resp = req_lib.post(gs_url, json=data, timeout=10)
        return jsonify({'ok': True, 'response': resp.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
