# change_cookie.py - Enhanced and Corrected Version

import hashlib
import json
import os
import random
import ssl
import time
from urllib.parse import parse_qs, urlparse

import requests
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# This will be used if cookie_config.py is not found or is empty.
DEFAULT_COOKIE_POOL = [
    {"datadome": "7upHF1~A_valid_fallback_cookie_if_needed_1"},
    {"datadome": "ARowvR~A_valid_fallback_cookie_if_needed_2"}
]
try:
    from cookie_config import COOKIE_POOL, STATIC_FALLBACK_TOKEN
except ImportError:
    print(f"{Fore.YELLOW}[WARNING] cookie_config.py not found. Using default values.{Style.RESET_ALL}")
    COOKIE_POOL = DEFAULT_COOKIE_POOL
    STATIC_FALLBACK_TOKEN = "a_static_fallback_token_string_32_chars"


DATADOME_JSON = os.path.join(os.path.dirname(__file__), "datadome_cookies.json")
TOKEN_JSON = os.path.join(os.path.dirname(__file__), "token_sessions.json")
MAX_TOKENS_TO_STORE = 1000

def random_delay():
    """Add random delay between requests"""
    time.sleep(random.uniform(1.5, 3.5))

class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.ssl_context = self._create_ssl_context()
        super().__init__(*args, **kwargs)
    
    def _create_ssl_context(self):
        """Create more compatible SSL context"""
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    def init_poolmanager(self, connections, maxsize, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(connections, maxsize, **kwargs)

def configure_tls_fingerprint(session):
    """Configure TLS fingerprint for requests session using custom adapter"""
    adapter = CustomHTTPAdapter(max_retries=Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    ))
    session.mount("https://", adapter)
    session.mount("http://", adapter)

def load_datadome_pool():
    """Load datadome cookies from JSON file, ensuring correct format."""
    try:
        if os.path.exists(DATADOME_JSON):
            with open(DATADOME_JSON, 'r') as f:
                data = json.load(f)
                # Ensure data from file is a list of dictionaries
                if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                    return data
    except Exception as e:
        print(f"{Fore.YELLOW}[WARNING] Failed to load datadome cookies: {e}{Style.RESET_ALL}")
    
    # Fallback to COOKIE_POOL, ensuring it is in the correct format
    if isinstance(COOKIE_POOL, list):
        # If it's a list of strings, convert it.
        if all(isinstance(c, str) for c in COOKIE_POOL):
            return [{'datadome': c} for c in COOKIE_POOL]
        # If it's already a list of dicts, return it.
        if all(isinstance(c, dict) for c in COOKIE_POOL):
            return COOKIE_POOL

    return DEFAULT_COOKIE_POOL # Absolute fallback

def save_new_datadome(datadome_cookie):
    """Save a new datadome cookie to the JSON file"""
    try:
        existing_cookies = load_datadome_pool()
        if any(c.get("datadome") == datadome_cookie for c in existing_cookies):
            return False
            
        existing_cookies.append({"datadome": datadome_cookie})
        with open(DATADOME_JSON, 'w') as f:
            json.dump(existing_cookies, f, indent=2)
        print(f"\n{Fore.CYAN}[INFO] New DataDome cookie saved to {DATADOME_JSON}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to save datadome cookie: {e}{Style.RESET_ALL}")
        return False

class EnhancedCookieRotator:
    def __init__(self):
        self.cookie_pool = load_datadome_pool()
        # **FIX:** Add a safety check to ensure all items are dictionaries with the 'datadome' key
        self.cookie_pool = [c for c in self.cookie_pool if isinstance(c, dict) and 'datadome' in c]
        
        self.usage_counts = {c['datadome']: 0 for c in self.cookie_pool}
        self.last_used = {}
        self.blacklist = set()
        self.cookie_health = {c['datadome']: 100 for c in self.cookie_pool}
        self.cookie_success_rates = {c['datadome']: [] for c in self.cookie_pool}
        
    def get_optimal_cookie(self):
        """Enhanced cookie selection with health scoring"""
        if not self.cookie_pool:
            print(f"{Fore.RED}[ERROR] No valid datadome cookies available to use.{Style.RESET_ALL}")
            return None # Return None if pool is empty

        available = [c for c in self.cookie_pool 
                    if (c['datadome'] not in self.blacklist and 
                        self.cookie_health.get(c['datadome'], 100) > 50)]
        
        if not available:
            self.blacklist = set()
            available = self.cookie_pool
        
        if not available: # Double check in case pool was empty to begin with
            return None

        available.sort(key=lambda x: (
            -self.cookie_health.get(x['datadome'], 0),
            self.usage_counts.get(x['datadome'], 0),
            self.last_used.get(x['datadome'], 0)
        ))
        
        selected = available[0]
        self.usage_counts[selected['datadome']] += 1
        self.last_used[selected['datadome']] = time.time()
        return selected['datadome']
        
    def report_failure(self, cookie):
        """Mark a cookie as potentially bad"""
        if cookie is None: return
        self.blacklist.add(cookie)
        self.update_cookie_health(cookie, False)
        
        fail_count = sum(1 for k in self.blacklist if k == cookie)
        if fail_count > 3:
            self.cookie_pool = [c for c in self.cookie_pool if c['datadome'] != cookie]

    def update_cookie_health(self, cookie, success):
        """Update cookie health based on request outcome"""
        if cookie not in self.cookie_success_rates:
            return
            
        self.cookie_success_rates[cookie].append(1 if success else 0)
        self.cookie_success_rates[cookie] = self.cookie_success_rates[cookie][-10:]
        
        if self.cookie_success_rates[cookie]:
            success_rate = sum(self.cookie_success_rates[cookie]) / len(self.cookie_success_rates[cookie])
            current_health = self.cookie_health.get(cookie, 100)
            self.cookie_health[cookie] = int((current_health * 0.7) + (success_rate * 100 * 0.3))

class RequestThrottler:
    def __init__(self):
        self.last_request_time = 0
        self.request_history = []
        self.error_count = 0
        self.max_retries = 3
        
    def calculate_delay(self):
        """Calculate dynamic delay with exponential backoff for errors"""
        if self.error_count > 0:
            return min(60, 2 ** self.error_count + random.uniform(0.5, 1.5))
            
        if not self.request_history:
            return random.uniform(2.0, 4.0)
            
        avg_interval = sum(self.request_history) / len(self.request_history)
        return max(1.5, avg_interval * 1.2 + random.uniform(-0.5, 1.0))
        
    def wait_if_needed(self):
        """Sleep if needed to maintain healthy request rate"""
        now = time.time()
        if self.last_request_time > 0:
            elapsed = now - self.last_request_time
            self.request_history.append(elapsed)
            self.request_history = self.request_history[-10:]
            
        delay = self.calculate_delay()
        time.sleep(delay)
        self.last_request_time = time.time()
        
    def record_error(self):
        """Call this when a request fails"""
        self.error_count += 1
        if self.error_count >= self.max_retries:
            cool_down = random.randint(30, 60)
            print(f"{Fore.YELLOW}[WARNING] Too many errors - cooling down for {cool_down} seconds{Style.RESET_ALL}")
            time.sleep(cool_down)
            self.error_count = 0
            
    def record_success(self):
        """Call this when a request succeeds"""
        self.error_count = 0

class SmartSessionManager:
    def __init__(self):
        self.session_pool = []
        self.max_sessions = 5
        self.session_timeout = 300
        
    def get_session(self):
        """Get or create a session with rotation"""
        now = time.time()
        self.session_pool = [s for s in self.session_pool 
                           if now - s['last_used'] < self.session_timeout]
                           
        if not self.session_pool or len(self.session_pool) < self.max_sessions:
            session = requests.Session()
            configure_tls_fingerprint(session)
            session_obj = {
                'session': session,
                'usage_count': 0,
                'last_used': now,
                'created_at': now
            }
            self.session_pool.append(session_obj)
            return session_obj
            
        self.session_pool.sort(key=lambda x: (x['usage_count'], x['last_used']))
        return self.session_pool[0]
        
    def make_request(self, method, url, **kwargs):
        """Make request with session rotation"""
        session_obj = self.get_session()
        session = session_obj['session']
        kwargs['verify'] = False
        
        for attempt in range(3):
            try:
                throttler.wait_if_needed()
                response = session.request(method, url, **kwargs)
                session_obj['usage_count'] += 1
                session_obj['last_used'] = time.time()
                throttler.record_success()
                
                if response.status_code == 429 or 'captcha' in response.text.lower():
                    throttler.record_error()
                    if 'cookies' in kwargs:
                        kwargs['cookies']['datadome'] = cookie_rotator.get_optimal_cookie()
                    continue
                    
                return response
            except requests.exceptions.SSLError as e:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
            except Exception as e:
                throttler.record_error()
                self.session_pool = [s for s in self.session_pool if s != session_obj]
                if attempt == 2:
                    raise
                time.sleep(1)

class EnhancedTokenManager:
    def __init__(self):
        self.token_cache = []
        self.last_refresh = 0
        self.token_expiry = 1800
        self.token_quality = {}
        self.token_origin = {}
        self.session = requests.Session()
        configure_tls_fingerprint(self.session)
        
    def get_fresh_token(self):
        """Enhanced token generation with quality tracking"""
        try:
            tokens = set()
            for _ in range(3):
                response = self.session.get(
                    "https://auth.garena.com/universal/oauth?client_id=10017",
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    timeout=10
                )
                if token := response.cookies.get('token_session'):
                    tokens.add(token)
                    self.token_quality[token] = 100
                    self.token_origin[token] = 'fresh'
                    save_new_token(token)
            
            if tokens:
                self.token_cache.extend(tokens)
                self.token_cache = self.token_cache[-15:]
                return self.select_best_token(list(tokens))
            
            return STATIC_FALLBACK_TOKEN
        except Exception:
            return STATIC_FALLBACK_TOKEN
            
    def select_best_token(self, tokens):
        """Select token with highest quality score"""
        if not tokens:
            return random.choice(self.token_cache) if self.token_cache else STATIC_FALLBACK_TOKEN
            
        scored_tokens = [(t, self.token_quality.get(t, 50)) for t in tokens]
        scored_tokens.sort(key=lambda x: -x[1])
        return scored_tokens[0][0]
    
    def update_token_quality(self, token, success):
        """Update token quality based on usage"""
        if token in self.token_quality:
            current_quality = self.token_quality[token]
            if success:
                self.token_quality[token] = min(100, current_quality + 5)
            else:
                self.token_quality[token] = max(0, current_quality - 20)
    
    def get_valid_token(self):
        """Get token with cache rotation"""
        if self.token_cache and (time.time() - self.last_refresh) < self.token_expiry:
            return self.select_best_token(self.token_cache)
            
        self.token = self.get_fresh_token()
        self.last_refresh = time.time()
        return self.token

class EnhancedAcSessionManager:
    def __init__(self):
        self.current_session = None
        self.last_refreshed = 0
        self.session_ttl = 1800
        self.session_cache = {}
        self.session = requests.Session()
        configure_tls_fingerprint(self.session)

        retry_strategy = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _generate_new_ac_session(self, auth_cookies):
        """Internal method to fetch fresh ac_session from account page"""
        cookies_hash = self._hash_auth_cookies(auth_cookies)
        
        for attempt in range(3):
            try:  
                account_url = "https://account.garena.com/api/account/init"
                response = self.session.get(
                    account_url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'X-Requested-With': 'XMLHttpRequest',
                        'Accept': 'application/json'
                    },
                    cookies=auth_cookies,
                    timeout=10
                )
                
                if response.status_code == 200:
                    new_session = response.cookies.get('ac_session')
                    if new_session:
                        self.session_cache[cookies_hash] = {
                            'session': new_session,
                            'expires': time.time() + self.session_ttl
                        }
                        return new_session
            except Exception as e:
                if attempt == 2:
                    print(f"{Fore.RED}[AC_SESSION ERROR] Generation failed: {e}{Style.RESET_ALL}")
        return None
        
    def get_valid_ac_session(self, auth_cookies=None, force_fresh=False):
        """Get session token with option to force refresh"""
        if not auth_cookies:
            raise ValueError("auth_cookies required for ac_session generation")
            
        cookies_hash = self._hash_auth_cookies(auth_cookies)
        cached_session = self.session_cache.get(cookies_hash)
        
        if (force_fresh or 
            not cached_session or 
            time.time() > cached_session['expires']):
            
            print(f"{Fore.MAGENTA}[+] Generating fresh ac_session...{Style.RESET_ALL}")
            new_session = self._generate_new_ac_session(auth_cookies)
            
            if new_session:
                return new_session
        
        return cached_session['session'] if cached_session else ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
    
    def _hash_auth_cookies(self, auth_cookies):
        """Create a hash of auth cookies for caching"""
        return hashlib.md5(json.dumps(auth_cookies, sort_keys=True).encode()).hexdigest()

class SessionKeyManager:
    def __init__(self):
        self.key_cache = {}
        self.key_ttl = 3600
        
    def extract_sso_key(self, set_cookie_header):
        """Robust SSO key extraction"""
        if not set_cookie_header:
            return None
            
        try:
            if isinstance(set_cookie_header, list):
                for cookie in set_cookie_header:
                    if 'sso_key=' in cookie:
                        return cookie.split('sso_key=')[1].split(';')[0]
            elif 'sso_key=' in set_cookie_header:
                return set_cookie_header.split('sso_key=')[1].split(';')[0]
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] SSO key extraction failed: {e}{Style.RESET_ALL}")
        return None
        
    def cache_session_key(self, session_key, sso_key):
        """Cache session keys with SSO key association"""
        if not session_key or not sso_key:
            return
            
        cache_key = hashlib.md5(sso_key.encode()).hexdigest()
        self.key_cache[cache_key] = {
            'session_key': session_key,
            'sso_key': sso_key,
            'expires': time.time() + self.key_ttl
        }
        
    def get_cached_session_key(self, sso_key):
        """Retrieve cached session key"""
        if not sso_key:
            return None
            
        cache_key = hashlib.md5(sso_key.encode()).hexdigest()
        cached = self.key_cache.get(cache_key)
        if cached and time.time() < cached['expires']:
            return cached['session_key']
        return None

class CookieMonitor:
    def __init__(self):
        self.cookie_performance = {}
        
    def track_cookie_performance(self, cookie_type, cookie_value, success):
        """Track performance of different cookie types"""
        if cookie_type not in self.cookie_performance:
            self.cookie_performance[cookie_type] = {}
            
        if cookie_value not in self.cookie_performance[cookie_type]:
            self.cookie_performance[cookie_type][cookie_value] = {
                'success': 0,
                'failures': 0,
                'last_used': time.time()
            }
            
        if success:
            self.cookie_performance[cookie_type][cookie_value]['success'] += 1
        else:
            self.cookie_performance[cookie_type][cookie_value]['failures'] += 1
            
        self.cookie_performance[cookie_type][cookie_value]['last_used'] = time.time()
        
    def get_cookie_success_rate(self, cookie_type, cookie_value):
        """Get success rate for a specific cookie"""
        if (cookie_type in self.cookie_performance and 
            cookie_value in self.cookie_performance[cookie_type]):
            stats = self.cookie_performance[cookie_type][cookie_value]
            total = stats['success'] + stats['failures']
            return stats['success'] / total if total > 0 else 0
        return None
        
    def cleanup_old_cookies(self, max_age=86400):
        """Remove old cookie performance data"""
        now = time.time()
        for cookie_type in list(self.cookie_performance.keys()):
            for cookie_value in list(self.cookie_performance[cookie_type].keys()):
                if now - self.cookie_performance[cookie_type][cookie_value]['last_used'] > max_age:
                    del self.cookie_performance[cookie_type][cookie_value]

def load_token_pool():
    """Load saved tokens from JSON file"""
    try:
        if os.path.exists(TOKEN_JSON):
            with open(TOKEN_JSON, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Failed to load tokens: {e}")
        return []

def save_new_token(token):
    """Save a new token to the JSON file without duplicates"""
    try:
        if not token or len(token) < 30:
            return False
            
        existing_tokens = load_token_pool()
        
        if token in existing_tokens:
            return False
            
        updated_tokens = [token] + existing_tokens
        updated_tokens = updated_tokens[:MAX_TOKENS_TO_STORE]
        
        with open(TOKEN_JSON, 'w') as f:
            json.dump(updated_tokens, f, indent=2)
            
        print(f"\n{Fore.CYAN}[INFO] New token session saved to {TOKEN_JSON}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"Failed to save new token: {e}")
        return False

def generate_enhanced_dynamic_cookies(auth_cookies=None):
    """Generate cookies with intelligent rotation and quality tracking"""
    timestamp = int(time.time())
    
    cookies = {
        "_ga": f"GA1.1.{timestamp}.{timestamp - 100000}",
        "_ga_57E30E1PMN": f"GS1.2.{timestamp}.1.0.{timestamp}.0.0.0",
        "_ga_G8QGMJPWWV": f"GS1.1.{timestamp + 1000}.1.1.{timestamp + 2000}.0.0.0",
        "token_session": token_manager.get_valid_token(),
        "datadome": cookie_rotator.get_optimal_cookie(),
    }
    
    if auth_cookies:
        try:
            cookies["ac_session"] = ac_session_manager.get_valid_ac_session(auth_cookies)
            cookies["sso_key"] = auth_cookies.get("sso_key", "")
            
            if "sso_key" in cookies:
                if session_key := session_key_manager.get_cached_session_key(cookies["sso_key"]):
                    cookies["session_key"] = session_key
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Failed to generate auth cookies: {e}{Style.RESET_ALL}")
            
    return cookies

def validate_cookies(cookies):
    """Enhanced cookie validation with fingerprint checks"""
    required = ["_ga", "token_session", "datadome"]
    if not all(cookie in cookies for cookie in required):
        return False
    if not isinstance(cookies.get('token_session'), str) or len(cookies['token_session']) < 30:
        return False
    if cookies.get('datadome') is None: # Can be None if pool is empty
        return False
    return True

def handle_captcha_with_fresh_datadome(cookies, headers):
    """Handle CAPTCHA by rotating datadome cookies"""
    try:
        fresh_options = [c for c in load_datadome_pool() 
                       if isinstance(c, dict) and c.get('datadome') != cookies.get('datadome')]
        
        if not fresh_options:
            return cookies, headers, "no_fresh_available"
            
        selected = random.choice(fresh_options)
        new_cookies = {**cookies, 'datadome': selected['datadome']}
        
        if not any(c['datadome'] == selected['datadome'] for c in COOKIE_POOL):
            save_new_datadome(selected['datadome'])
        
        new_headers = headers.copy()
        new_headers.update({
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        
        return new_cookies, new_headers, "rotated"
    except Exception as e:
        print(f"{Fore.RED}[CAPTCHA ERROR] {e}{Style.RESET_ALL}")
        return cookies, headers, "error"

def save_cookies(cookies, filename="cookies.json"):
    try:
        # Load existing cookies if file exists
        existing_cookies = []
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                existing_cookies = json.load(f)
                if not isinstance(existing_cookies, list):
                    existing_cookies = [existing_cookies]
        
        # Check for duplicates before adding
        if not any(c == cookies for c in existing_cookies):
            existing_cookies.append(cookies)
            
            # Keep only the most recent cookies
            existing_cookies = existing_cookies[-100:]
            
            with open(filename, 'w') as f:
                json.dump(existing_cookies, f, indent=2)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to save cookies: {e}{Style.RESET_ALL}")

def load_cookies(filename="cookies.json"):
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                all_cookies = json.load(f)
                if isinstance(all_cookies, list) and all_cookies:
                    # Return the most recent valid cookie
                    for cookies in reversed(all_cookies):
                        if validate_cookies(cookies):
                            return cookies
    except Exception as e:
        print(f"{Fore.YELLOW}[WARNING] Failed to load cookies: {e}{Style.RESET_ALL}")
    return None

def get_cookies():
    """Main cookie getter with fallbacks"""
    saved = load_cookies()
    if saved:
        return saved
    return generate_enhanced_dynamic_cookies()

# Backward compatibility functions
def generate_dynamic_cookies(auth_cookies=None):
    """Legacy function - uses enhanced generator"""
    return generate_enhanced_dynamic_cookies(auth_cookies)

# Initialize all managers
cookie_rotator = EnhancedCookieRotator()
throttler = RequestThrottler()
session_manager = SmartSessionManager()
token_manager = EnhancedTokenManager()
ac_session_manager = EnhancedAcSessionManager()
session_key_manager = SessionKeyManager()
cookie_monitor = CookieMonitor()