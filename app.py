import os, json, bcrypt, jwt, base64, io, math
from urllib.parse import urlencode
import requests as req_lib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, redirect
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

def make_token(user):
    payload = {'id': user['id'], 'email': user['email'], 'role': user['role'], 'name': user.get('name',''), 'exp': datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token():
    auth = request.headers.get('Authorization','')
    if not auth.startswith('Bearer '): return None
    try: return jwt.decode(auth[7:], JWT_SECRET, algorithms=['HS256'])
    except: return None

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

def refresh_google_token(user_id, access_token, refresh_token):
    test = req_lib.get('https://www.googleapis.com/oauth2/v1/tokeninfo', params={'access_token': access_token}, timeout=5)
    if test.status_code != 200 and refresh_token:
        ref = req_lib.post('https://oauth2.googleapis.com/token', data={
            'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET,
            'refresh_token': refresh_token, 'grant_type': 'refresh_token'
        }, timeout=10)
        if ref.status_code == 200:
            new_token = ref.json().get('access_token', access_token)
            sb.table('users').update({'google_access_token': new_token}).eq('id', user_id).execute()
            return new_token
    return access_token

def get_user_google_token(user_id):
    user_res = sb.table('users').select('google_access_token,google_refresh_token').eq('id', user_id).execute()
    if not user_res.data or not user_res.data[0].get('google_access_token'):
        return None, None
    at = user_res.data[0]['google_access_token']
    rt = user_res.data[0].get('google_refresh_token','')
    at = refresh_google_token(user_id, at, rt)
    return at, rt

# ── XLSX PARSE ───────────────────────────────────────────
@app.route('/api/xlsx/parse', methods=['POST'])
@require_auth
def parse_xlsx():
    try:
        import pandas as pd
        data = request.json
        raw = base64.b64decode(data.get('data',''))
        xl = pd.ExcelFile(io.BytesIO(raw))
        valid = [s for s in xl.sheet_names if not s.strip().lower().startswith('sayfa') or not s[5:].strip().isdigit()]
        sheets_info = {}
        for sheet in valid:
            df = pd.read_excel(io.BytesIO(raw), sheet_name=sheet, header=1)
            tel_col = next((c for c in df.columns if 'tel' in str(c).lower()), None)
            if tel_col:
                df = df[df[tel_col].notna()].copy()
                def is_valid_tel(x):
                    try: return len(str(int(float(x)))) >= 7
                    except: return False
                df = df[df[tel_col].apply(is_valid_tel)].copy()
                df[tel_col] = df[tel_col].apply(lambda x: str(int(float(x))) if pd.notna(x) else '')
            df = df.where(pd.notna(df), None)
            seen_cols = {}; col_names = []
            for col in df.columns:
                if str(col).startswith('Unnamed'): col_names.append(None); continue
                col_str = str(col)
                if col_str in seen_cols: seen_cols[col_str] += 1; col_names.append(f"{col_str}_{seen_cols[col_str]}")
                else: seen_cols[col_str] = 0; col_names.append(col_str)
            rows = []
            for i, (_, row) in enumerate(df.iterrows()):
                r = {'_row': i+1}
                for j, col_name in enumerate(col_names):
                    if col_name is None: continue
                    val = row.iloc[j]
                    r[col_name] = None if (isinstance(val, float) and math.isnan(val)) else (str(val) if val is not None else None)
                rows.append(r)
            sheets_info[sheet] = {'columns': [c for c in df.columns if not str(c).startswith('Unnamed')], 'rows': rows, 'count': len(rows)}
        return jsonify({'sheets': valid, 'data': sheets_info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── GOOGLE AUTH ──────────────────────────────────────────
@app.route('/auth/google/login')
def google_login():
    params = {'client_id': GOOGLE_CLIENT_ID, 'redirect_uri': GOOGLE_REDIRECT_URI, 'response_type': 'code',
              'scope': 'openid email profile https://www.googleapis.com/auth/contacts https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive.readonly',
              'access_type': 'offline', 'prompt': 'consent'}
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params))

@app.route('/auth/google/callback')
def google_callback():
    code = request.args.get('code')
    if not code: return redirect('/?error=no_code')
    token_res = req_lib.post('https://oauth2.googleapis.com/token', data={
        'code': code, 'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI, 'grant_type': 'authorization_code'
    })
    tokens = token_res.json()
    access_token = tokens.get('access_token','')
    refresh_token = tokens.get('refresh_token','')
    userinfo = req_lib.get('https://www.googleapis.com/oauth2/v2/userinfo', headers={'Authorization': f'Bearer {access_token}'}).json()
    email = userinfo.get('email','').lower()
    name = userinfo.get('name','')
    if not email: return redirect('/?error=no_email')
    user_res = sb.table('users').select('*').eq('email', email).execute()
    if not user_res.data: return redirect('/?error=not_found')
    user = user_res.data[0]
    sb.table('users').update({'google_access_token': access_token, 'google_refresh_token': refresh_token, 'name': name or user.get('name','')}).eq('id', user['id']).execute()
    jwt_token = make_token(user)
    return f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><script>
try{{localStorage.setItem('token','{jwt_token}');}}catch(e){{}}
window.location.replace('/');
</script></head><body>Yonlendiriliyor...</body></html>'''

# ── GOOGLE CONTACTS ──────────────────────────────────────
@app.route('/api/google/contacts/add', methods=['POST'])
@require_auth
def add_to_google_contacts():
    try:
        import uuid, time as _t
        data = request.json
        user_id = request.user['id']
        access_token, _ = get_user_google_token(user_id)
        if not access_token: return jsonify({'error': 'Google bağlı değil', 'needs_auth': True}), 401
        contacts = data.get('contacts', [])
        def normalize_tel(tel):
            t = ''.join(filter(str.isdigit, str(tel)))
            if t.startswith('90') and len(t)==12: return '+'+t
            if t.startswith('0') and len(t)==11: return '+9'+t
            if len(t)==10: return '+90'+t
            return '+'+t
        added = 0; errors = 0
        for i in range(0, len(contacts), 50):
            batch = contacts[i:i+50]
            boundary = f'batch_{uuid.uuid4().hex}'
            body_parts = []
            for c in batch:
                tel = normalize_tel(c.get('tel',''))
                if not tel: continue
                contact_body = json.dumps({'names': [{'displayName': c.get('name',''), 'givenName': c.get('name','')}], 'phoneNumbers': [{'value': tel, 'type': 'mobile'}]})
                body_parts.append(f'--{boundary}\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\nPOST /v1/people:createContact HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{contact_body}\r\n')
            if not body_parts: continue
            body_parts.append(f'--{boundary}--')
            try:
                r = req_lib.post('https://people.googleapis.com/batch', data=''.join(body_parts).encode('utf-8'),
                    headers={'Authorization': f'Bearer {access_token}', 'Content-Type': f'multipart/mixed; boundary={boundary}'}, timeout=60)
                batch_count = len(body_parts) - 1
                if r.status_code == 401: return jsonify({'error': 'Token süresi doldu', 'needs_auth': True}), 401
                if r.status_code == 200 and 'RESOURCE_EXHAUSTED' not in r.text: added += batch_count
                elif 'RESOURCE_EXHAUSTED' in r.text or r.status_code == 429:
                    _t.sleep(60)
                    r2 = req_lib.post('https://people.googleapis.com/batch', data=''.join(body_parts).encode('utf-8'),
                        headers={'Authorization': f'Bearer {access_token}', 'Content-Type': f'multipart/mixed; boundary={boundary}'}, timeout=60)
                    if r2.status_code == 200 and 'RESOURCE_EXHAUSTED' not in r2.text: added += batch_count
                    else: errors += batch_count
                else: errors += batch_count
            except Exception as e: errors += len(batch)
            _t.sleep(20)
        return jsonify({'ok': True, 'added': added, 'errors': errors, 'total_sent': len(contacts)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── DRIVE API ────────────────────────────────────────────
@app.route('/api/drive/sheets', methods=['GET'])
@require_auth
def list_drive_sheets():
    try:
        access_token, _ = get_user_google_token(request.user['id'])
        if not access_token: return jsonify({'error': 'Google bağlı değil', 'needs_auth': True}), 401
        r = req_lib.get('https://www.googleapis.com/drive/v3/files',
            params={'q': "mimeType='application/vnd.google-apps.spreadsheet' and trashed=false", 'fields': 'files(id,name,modifiedTime)', 'orderBy': 'modifiedTime desc', 'pageSize': 100},
            headers={'Authorization': f'Bearer {access_token}'}, timeout=15)
        if r.status_code != 200: return jsonify({'error': f'Drive hatası: {r.text[:200]}'}), 400
        return jsonify({'files': r.json().get('files', [])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SHEETS PAGES ─────────────────────────────────────────
@app.route('/api/sheets/pages', methods=['GET'])
@require_auth
def get_sheet_pages():
    try:
        access_token, _ = get_user_google_token(request.user['id'])
        if not access_token: return jsonify({'error': 'Google bağlı değil'}), 401
        spreadsheet_id = request.args.get('spreadsheet_id','')
        if not spreadsheet_id: return jsonify({'error': 'spreadsheet_id gerekli'}), 400
        r = req_lib.get(f'https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}',
            params={'fields': 'sheets.properties.title'}, headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        if r.status_code != 200: return jsonify({'error': r.text[:200]}), 400
        return jsonify({'sheets': [s['properties']['title'] for s in r.json().get('sheets', [])]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SHEETS WRITE ─────────────────────────────────────────
@app.route('/api/sheets/write', methods=['POST'])
@require_auth
def sheets_write():
    try:
        data = request.json
        access_token, _ = get_user_google_token(request.user['id'])
        if not access_token: return jsonify({'error': 'Google bağlı değil', 'needs_auth': True}), 401
        spreadsheet_id = data.get('spreadsheet_id','')
        sheet_name = data.get('sheet','')
        tel = str(data.get('tel','')).replace(' ','')
        sonuc = data.get('sonuc',''); donus = data.get('donus',''); not_text = data.get('not','')
        if not spreadsheet_id: return jsonify({'error': 'Sheets ID girilmemiş'}), 400
        headers = {'Authorization': f'Bearer {access_token}'}
        range_name = f"'{sheet_name}'!B3:B" if sheet_name else 'B3:B'
        r = req_lib.get(f'https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/{range_name}', headers=headers, timeout=15)
        if r.status_code != 200: return jsonify({'error': f'Sheets okuma hatası: {r.text[:200]}'}), 400
        values = r.json().get('values', [])
        clean_tel = ''.join(filter(str.isdigit, tel))
        row_num = None
        for i, row in enumerate(values):
            if row:
                row_tel = ''.join(filter(str.isdigit, str(row[0])))
                if row_tel == clean_tel or row_tel.endswith(clean_tel[-10:]) or clean_tel.endswith(row_tel[-10:]):
                    row_num = i + 3; break
        if not row_num: return jsonify({'error': f'Tel bulunamadı: {tel}'}), 404
        sheet_prefix = f"'{sheet_name}'!" if sheet_name else ''
        updates = []
        if sonuc: updates.append({'range': f'{sheet_prefix}C{row_num}', 'values': [[sonuc]]})
        if donus: updates.append({'range': f'{sheet_prefix}D{row_num}', 'values': [[donus]]})
        if not_text: updates.append({'range': f'{sheet_prefix}E{row_num}', 'values': [[not_text]]})
        if updates:
            r2 = req_lib.post(f'https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values:batchUpdate',
                json={'valueInputOption': 'USER_ENTERED', 'data': updates}, headers=headers, timeout=15)
            if r2.status_code != 200: return jsonify({'error': f'Yazma hatası: {r2.text[:200]}'}), 400
        return jsonify({'ok': True, 'row': row_num})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SHEETS IMPORT ─────────────────────────────────────────
@app.route('/api/sheets/import', methods=['POST'])
@require_auth
def sheets_import():
    try:
        data = request.json
        user_id = request.user['id']
        spreadsheet_id = data.get('spreadsheet_id','')
        sheet_name = data.get('sheet','')
        list_name = data.get('name','')
        list_id = data.get('list_id', None)
        update_only = data.get('update_only', False)
        if not spreadsheet_id or not sheet_name: return jsonify({'error': 'spreadsheet_id ve sheet gerekli'}), 400
        access_token, _ = get_user_google_token(user_id)
        if not access_token: return jsonify({'error': 'Google bağlı değil', 'needs_auth': True}), 401
        r = req_lib.get(f'https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/{chr(39)}{sheet_name}{chr(39)}!A3:E',
            headers={'Authorization': f'Bearer {access_token}'}, timeout=15)
        if r.status_code != 200: return jsonify({'error': f'Sheets okuma hatası: {r.text[:200]}'}), 400
        values = r.json().get('values', [])
        if update_only and list_id:
            lid = list_id
            sb.table('contacts').delete().eq('list_id', lid).execute()
        else:
            lst_res = sb.table('data_lists').insert({'name': list_name, 'sheet': sheet_name, 'assigned_to': user_id, 'created_by': user_id, 'spreadsheet_id': spreadsheet_id}).execute()
            if not lst_res.data: return jsonify({'error': 'Liste oluşturulamadı'}), 500
            lid = lst_res.data[0]['id']
        batch = []
        for i, row in enumerate(values):
            name = row[0].strip() if len(row) > 0 else ''
            tel = ''.join(filter(str.isdigit, str(row[1]))) if len(row) > 1 else ''
            if not tel: continue
            batch.append({'list_id': lid, 'row_index': i+1, 'name': name, 'tel': tel, 'extra': {},
                'sonuc': row[2].strip() if len(row) > 2 and row[2].strip() else None,
                'donus': row[3].strip() if len(row) > 3 and row[3].strip() else None,
                'not_text': row[4].strip() if len(row) > 4 else ''})
            if len(batch) >= 200:
                sb.table('contacts').insert(batch).execute(); batch = []
        if batch: sb.table('contacts').insert(batch).execute()
        return jsonify({'ok': True, 'count': len(values), 'list_id': lid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SHEETS PROXY ─────────────────────────────────────────
@app.route('/api/sheets/send', methods=['POST'])
@require_auth
def sheets_send():
    try:
        data = request.json
        list_id = data.get('list_id')
        gs_url = ''
        if list_id:
            list_res = sb.table('data_lists').select('gs_url').eq('id', list_id).execute()
            if list_res.data: gs_url = list_res.data[0].get('gs_url','')
        if not gs_url:
            settings_res = sb.table('settings').select('gs_url').limit(1).execute()
            if settings_res.data: gs_url = settings_res.data[0].get('gs_url','')
        if not gs_url: return jsonify({'error': 'Google Sheets URL ayarlanmamış'}), 400
        resp = req_lib.post(gs_url, json=data, timeout=10, allow_redirects=True)
        return jsonify({'ok': True, 'response': resp.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── STATIC ───────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# ── LOGIN ────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email','').lower().strip()
    password = data.get('password','')
    res = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error':'Email veya sifre hatali'}), 401
    user = res.data[0]
    try: ok = bcrypt.checkpw(password.encode(), user['password'].encode())
    except: ok = (password == user['password'])
    if not ok: return jsonify({'error':'Email veya sifre hatali'}), 401
    return jsonify({'token': make_token(user), 'user': {'id': user['id'], 'email': user['email'], 'name': user.get('name',''), 'role': user['role']}})

@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    return jsonify(request.user)

# ── USERS ────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    user = request.user
    if user['role'] == 'admin':
        res = sb.table('users').select('id,email,name,role,created_at').execute()
    else:
        res = sb.table('users').select('id,name,role').eq('role','user').execute()
    return jsonify(res.data)

@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    data = request.json
    hashed = bcrypt.hashpw(data.get('password','').encode(), bcrypt.gensalt()).decode()
    res = sb.table('users').insert({'email': data.get('email','').lower().strip(), 'password': hashed, 'name': data.get('name',''), 'role': data.get('role','user')}).execute()
    return jsonify(res.data[0])

@app.route('/api/users/<uid>', methods=['DELETE'])
@require_admin
def delete_user(uid):
    try:
        lists = sb.table('data_lists').select('id').eq('assigned_to', uid).execute()
        for lst in (lists.data or []):
            sb.table('contacts').delete().eq('list_id', lst['id']).execute()
        sb.table('data_lists').delete().eq('assigned_to', uid).execute()
        sb.table('users').delete().eq('id', uid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<uid>/role', methods=['PUT'])
@require_admin
def change_role(uid):
    data = request.json
    sb.table('users').update({'role': data.get('role','user')}).eq('id', uid).execute()
    return jsonify({'ok': True})

@app.route('/api/users/<uid>/password', methods=['PUT'])
@require_admin
def change_password(uid):
    data = request.json
    hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    sb.table('users').update({'password': hashed}).eq('id', uid).execute()
    return jsonify({'ok': True})

# ── LISTS ────────────────────────────────────────────────
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
    res = sb.table('data_lists').insert({'name': data['name'], 'sheet': data.get('sheet',''), 'assigned_to': data.get('assigned_to'), 'created_by': request.user['id'], 'gs_url': data.get('gs_url',''), 'spreadsheet_id': data.get('spreadsheet_id','')}).execute()
    return jsonify(res.data[0])

@app.route('/api/lists/<lid>/spreadsheetid', methods=['PUT'])
@require_auth
def update_spreadsheet_id(lid):
    sb.table('data_lists').update({'spreadsheet_id': request.json.get('spreadsheet_id','')}).eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>/sheet', methods=['PUT'])
@require_auth
def update_list_sheet(lid):
    sb.table('data_lists').update({'sheet': request.json.get('sheet','')}).eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>/gsurl', methods=['PUT'])
@require_admin
def update_list_gsurl(lid):
    sb.table('data_lists').update({'gs_url': request.json.get('gs_url','')}).eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>', methods=['DELETE'])
@require_admin
def delete_list(lid):
    sb.table('contacts').delete().eq('list_id', lid).execute()
    sb.table('data_lists').delete().eq('id', lid).execute()
    return jsonify({'ok': True})

@app.route('/api/lists/<lid>/assign', methods=['PUT'])
@require_admin
def assign_list(lid):
    sb.table('data_lists').update({'assigned_to': request.json['user_id']}).eq('id', lid).execute()
    return jsonify({'ok': True})

# ── CONTACTS ─────────────────────────────────────────────
@app.route('/api/lists/<lid>/contacts', methods=['GET'])
@require_auth
def get_contacts(lid):
    user = request.user
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
    if not data.get('append', False):
        sb.table('contacts').delete().eq('list_id', lid).execute()
    batch = []
    for i, r in enumerate(rows):
        batch.append({'list_id': lid, 'row_index': int(r.get('row_index', i+1)), 'name': r.get('name',''), 'tel': r.get('tel',''), 'extra': r.get('extra', {}), 'sonuc': r.get('sonuc') or None, 'donus': r.get('donus') or None, 'not_text': r.get('not_text','') or ''})
        if len(batch) >= 500:
            sb.table('contacts').insert(batch).execute(); batch = []
    if batch: sb.table('contacts').insert(batch).execute()
    return jsonify({'ok': True, 'count': len(rows)})

@app.route('/api/contacts/<cid>/result', methods=['PUT'])
@require_auth
def update_result(cid):
    data = request.json
    update = {'updated_at': datetime.utcnow().isoformat()}
    if 'sonuc' in data: update['sonuc'] = data['sonuc']
    if 'donus' in data: update['donus'] = data['donus']
    if 'not_text' in data: update['not_text'] = data['not_text']
    sb.table('contacts').update(update).eq('id', cid).execute()
    return jsonify({'ok': True})

# ── STATS ────────────────────────────────────────────────
@app.route('/api/stats', methods=['GET'])
@require_admin
def get_stats():
    lists = sb.table('data_lists').select('id,name,assigned_to,users!assigned_to(name)').execute()
    result = []
    for lst in lists.data:
        contacts = sb.table('contacts').select('id,sonuc').eq('list_id', lst['id']).execute()
        total = len(contacts.data)
        done = len([c for c in contacts.data if c['sonuc']])
        sonuc_counts = {}
        for c in contacts.data:
            if c['sonuc']: sonuc_counts[c['sonuc']] = sonuc_counts.get(c['sonuc'], 0) + 1
        result.append({'list_id': lst['id'], 'list_name': lst['name'],
            'assigned_to': lst.get('users', {}).get('name','') if lst.get('users') else '',
            'user_name': lst.get('users', {}).get('name','') if lst.get('users') else '',
            'total': total, 'done': done, 'pct': round(done/total*100) if total else 0, 'sonuc_counts': sonuc_counts})
    return jsonify(result)

# ── SETTINGS ─────────────────────────────────────────────
@app.route('/api/settings', methods=['GET', 'PUT'])
@require_auth
def settings():
    if request.method == 'GET':
        res = sb.table('settings').select('*').limit(1).execute()
        if res.data: return jsonify(res.data[0])
        return jsonify({'timeout_sec': 25, 'delay_between_calls': 10, 'gs_url': ''})
    data = request.json
    existing = sb.table('settings').select('id').limit(1).execute()
    if existing.data: sb.table('settings').update(data).eq('id', existing.data[0]['id']).execute()
    else: sb.table('settings').insert(data).execute()
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
