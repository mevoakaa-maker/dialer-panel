import os, json, bcrypt, jwt, base64, io, math
from urllib.parse import urlencode
import requests as req_lib
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

GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI  = 'https://pasadialer.site/auth/google/callback'

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
            # Duplicate kolon isimlerini handle et
            seen_cols = {}
            col_names = []
            for col in df.columns:
                if str(col).startswith('Unnamed'):
                    col_names.append(None)
                    continue
                col_str = str(col)
                if col_str in seen_cols:
                    seen_cols[col_str] += 1
                    col_names.append(f"{col_str}_{seen_cols[col_str]}")
                else:
                    seen_cols[col_str] = 0
                    col_names.append(col_str)
            
            for i, (_, row) in enumerate(df.iterrows()):
                r = {'_row': i+1}
                for j, col_name in enumerate(col_names):
                    if col_name is None:
                        continue
                    val = row.iloc[j]
                    if isinstance(val, float) and math.isnan(val):
                        r[col_name] = None
                    else:
                        r[col_name] = str(val) if val is not None else None
                rows.append(r)
            sheets_info[sheet] = {
                'columns': [c for c in df.columns if not str(c).startswith('Unnamed')],
                'rows': rows,
                'count': len(rows)
            }
        return jsonify({'sheets': valid, 'data': sheets_info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── GOOGLE LOGIN ─────────────────────────────────────────
@app.route('/auth/google/login')
def google_login():
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile https://www.googleapis.com/auth/contacts',
        'access_type': 'offline',
        'prompt': 'consent',
    }
    from flask import redirect
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params))

# ── GOOGLE OAUTH ─────────────────────────────────────────
@app.route('/auth/google')
@require_auth
def google_auth():
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'https://www.googleapis.com/auth/contacts',
        'access_type': 'offline',
        'prompt': 'consent',
        'state': request.headers.get('Authorization','').replace('Bearer ','')
    }
    return jsonify({'url': 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)})

@app.route('/auth/google/callback')
def google_callback():
    code = request.args.get('code')
    if not code:
        return redirect('/?error=no_code')
    # Token al
    token_res = req_lib.post('https://oauth2.googleapis.com/token', data={
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    })
    tokens = token_res.json()
    access_token  = tokens.get('access_token','')
    refresh_token = tokens.get('refresh_token','')
    # Kullanıcı bilgisini al
    userinfo = req_lib.get('https://www.googleapis.com/oauth2/v2/userinfo',
        headers={'Authorization': f'Bearer {access_token}'}).json()
    email = userinfo.get('email','').lower()
    name  = userinfo.get('name','')
    if not email:
        return redirect('/?error=no_email')
    # Sistemde bu email var mı?
    user_res = sb.table('users').select('*').eq('email', email).execute()
    if not user_res.data:
        return redirect('/?error=not_found')
    user = user_res.data[0]
    # Google tokenları kaydet
    sb.table('users').update({
        'google_access_token': access_token,
        'google_refresh_token': refresh_token,
        'name': name or user.get('name', '')
    }).eq('id', user['id']).execute()
    # JWT token oluştur
    jwt_token = make_token(user)
    from flask import redirect as redir
    return redir(f'/?token={jwt_token}')

@app.route('/api/google/contacts/add', methods=['POST'])
@require_auth
def add_to_google_contacts():
    try:
        data = request.json
        user_id = request.user['id']
        user_res = sb.table('users').select('google_access_token,google_refresh_token').eq('id', user_id).execute()
        if not user_res.data or not user_res.data[0].get('google_access_token'):
            return jsonify({'error': 'Google bağlı değil', 'needs_auth': True}), 401
        access_token = user_res.data[0]['google_access_token']
        refresh_token = user_res.data[0].get('google_refresh_token','')
        
        # Token geçerli mi test et
        test = req_lib.get('https://www.googleapis.com/oauth2/v1/tokeninfo',
            params={'access_token': access_token}, timeout=5)
        if test.status_code != 200 and refresh_token:
            # Token süresi dolmuş, refresh et
            ref = req_lib.post('https://oauth2.googleapis.com/token', data={
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }, timeout=10)
            if ref.status_code == 200:
                access_token = ref.json().get('access_token', access_token)
                sb.table('users').update({'google_access_token': access_token}).eq('id', user_id).execute()
            else:
                return jsonify({'error': 'Token süresi doldu', 'needs_auth': True}), 401
        contacts = data.get('contacts', [])
        from concurrent.futures import ThreadPoolExecutor, as_completed
        added = 0
        errors = 0
        auth_expired = False

        import time as _time
        def normalize_tel(tel):
            t = ''.join(filter(str.isdigit, str(tel)))
            if t.startswith('90') and len(t)==12: return '+'+t
            if t.startswith('0') and len(t)==11: return '+9'+t
            if len(t)==10: return '+90'+t
            return '+'+t if not t.startswith('+') else tel

        def add_one(c):
            name = c.get('name','')
            tel  = normalize_tel(c.get('tel',''))
            if not tel: return 'skip'
            body = {
                'names': [{'displayName': name, 'givenName': name}],
                'phoneNumbers': [{'value': tel, 'type': 'mobile'}]
            }
            for attempt in range(3):
                try:
                    r = req_lib.post(
                        'https://people.googleapis.com/v1/people:createContact',
                        json=body,
                        headers={'Authorization': f'Bearer {access_token}'},
                        timeout=30
                    )
                    if r.status_code == 200: return 'ok'
                    elif r.status_code == 401: return 'auth'
                    elif r.status_code == 429:
                        _time.sleep(2 ** attempt)  # 1s, 2s, 4s
                        continue
                    else: return 'error'
                except Exception:
                    _time.sleep(1)
            return 'error'

        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = {ex.submit(add_one, c): c for c in contacts}
            for f in as_completed(futures):
                res = f.result()
                if res == 'ok': added += 1
                elif res == 'auth': auth_expired = True
                elif res == 'error': errors += 1

        if auth_expired:
            return jsonify({'error': 'Token süresi doldu', 'needs_auth': True}), 401
        return jsonify({'ok': True, 'added': added, 'errors': errors})
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
    # Cascade zaten Supabase'de ayarlı, direkt sil
    sb.table('contacts').delete().eq('list_id', lid).execute()
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
    res = sb.table('contacts').select('*').eq('list_id', lid).order('row_index', desc=False).execute()
    return jsonify(res.data)

@app.route('/api/lists/<lid>/contacts', methods=['POST'])
@require_auth
def upload_contacts(lid):
    data = request.json
    rows = data.get('rows', [])
    # Sadece ilk batch'te sil (append=True ise silme)
    if not data.get('append', False):
        sb.table('contacts').delete().eq('list_id', lid).execute()
    # Toplu ekle
    batch = []
    for i, r in enumerate(rows):
        batch.append({
            'list_id': lid,
            'row_index': int(r.get('row_index', i + 1)),
            'name': r.get('name',''),
            'tel': r.get('tel',''),
            'extra': r.get('extra', {}),
            'sonuc': r.get('sonuc') or None,
            'donus': r.get('donus') or None,
            'not_text': r.get('not_text','') or ''
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
    # timeout ve delay herkes değiştirebilir, gs_url sadece admin
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
        resp = req_lib.post(gs_url, json=data, timeout=10, allow_redirects=True)
        return jsonify({'ok': True, 'response': resp.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
