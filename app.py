import os, sqlite3, secrets, hashlib, hmac, time
from contextlib import contextmanager
from typing import Optional
from fastapi import FastAPI, Depends, Header, HTTPException, Path
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DB = os.getenv("SEV_DB_PATH", "./sev.sqlite3")
ADMIN_USER = os.getenv("SEV_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("SEV_ADMIN_PASSWORD", "")
SECRET = os.getenv("SEV_SECRET_KEY", "")
app = FastAPI(title="Phamquangios SEV", version="1.1.0")

@contextmanager
def conn():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def hashpw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return salt + "$" + digest

def verify(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
        return hmac.compare_digest(actual, digest)
    except Exception:
        return False

def session_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS accounts(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          max_devices INTEGER NOT NULL DEFAULT 1, locked INTEGER NOT NULL DEFAULT 0,
          key_active INTEGER NOT NULL DEFAULT 1, device_id TEXT, device_label TEXT,
          session_hash TEXT, created_at INTEGER NOT NULL, note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS devices(
          account_id INTEGER NOT NULL, device_id TEXT NOT NULL, device_label TEXT NOT NULL DEFAULT '',
          session_hash TEXT, last_seen INTEGER NOT NULL, locked INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(account_id, device_id),
          FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        columns = {r["name"] for r in c.execute("PRAGMA table_info(devices)")}
        if "locked" not in columns:
            c.execute("ALTER TABLE devices ADD COLUMN locked INTEGER NOT NULL DEFAULT 0")
        defaults = {
            "maintenance":"0",
            "maintenance_message":"Ứng dụng đang bảo trì. Vui lòng thử lại sau.",
            "update_url":"",
            "minimum_version":"1.0.0",
            "app_enabled":"1",
            "purchase_telegram":"https://t.me/phamquangioss",
            "developer":"PhamquangIoss / shenruisi / sty",
            "publisher":"Phamquangioss"
        }
        for k, v in defaults.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

init_db()

def setting(c, key):
    row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else ""

def version_tuple(v):
    out = []
    for part in (v or "0").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits or 0))
    return tuple((out + [0,0,0,0])[:4])

def require_available(c, version=None):
    if setting(c, "app_enabled") != "1":
        raise HTTPException(503, "Ứng dụng đang tạm thời đóng bởi nhà phát hành.")
    if setting(c, "maintenance") == "1":
        raise HTTPException(503, setting(c, "maintenance_message") or "Ứng dụng đang bảo trì.")
    minimum, update = setting(c, "minimum_version"), setting(c, "update_url")
    if version and minimum and update and version_tuple(version) < version_tuple(minimum):
        raise HTTPException(426, "Phiên bản app đã cũ. Hãy cập nhật tại: " + update)

def admin_auth(authorization: str = Header(default="")):
    if not ADMIN_PASSWORD or len(SECRET) < 32:
        raise HTTPException(503, "SEV chưa được cấu hình an toàn.")
    try:
        scheme, token = authorization.split(" ", 1)
        stamp, sig = token.split(".", 1)
        ts = int(stamp)
        expected = hmac.new(SECRET.encode(), (ADMIN_USER + ":" + stamp).encode(), "sha256").hexdigest()
        if scheme.lower() != "bearer" or not hmac.compare_digest(sig, expected):
            raise ValueError()
        if ts > int(time.time()) + 60 or ts < int(time.time()) - 28800:
            raise ValueError()
    except Exception:
        raise HTTPException(401, "Phiên quản trị không hợp lệ hoặc đã hết hạn.")
    return True

class AdminLogin(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
class CreateAccount(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    max_devices: int = Field(default=1, ge=1, le=100)
    note: str = Field(default="", max_length=500)
class AccountUpdate(BaseModel):
    max_devices: Optional[int] = Field(default=None, ge=1, le=100)
    locked: Optional[bool] = None
    key_active: Optional[bool] = None
    note: Optional[str] = Field(default=None, max_length=500)
class ResetPassword(BaseModel):
    password: str = Field(min_length=8, max_length=256)
class DeviceUpdate(BaseModel):
    locked: bool
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    device_id: str = Field(min_length=8, max_length=200)
    device_label: str = Field(default="iOS device", max_length=200)
    app_version: str = Field(default="1.0.0", max_length=40)
class ValidateRequest(BaseModel):
    session_token: str = Field(min_length=20, max_length=512)
    device_id: str = Field(min_length=8, max_length=200)
    app_version: str = Field(default="1.0.0", max_length=40)

@app.get("/health")
def health():
    return {"ok": True, "service": "Phamquangios SEV", "version": app.version}

@app.post("/api/admin/login")
def admin_login(data: AdminLogin):
    if not ADMIN_PASSWORD or len(SECRET) < 32:
        raise HTTPException(503, "Hãy cấu hình SEV_ADMIN_PASSWORD và SEV_SECRET_KEY.")
    if not hmac.compare_digest(data.username, ADMIN_USER) or not hmac.compare_digest(data.password, ADMIN_PASSWORD):
        raise HTTPException(401, "Sai tên hoặc mật khẩu quản trị.")
    stamp = str(int(time.time()))
    sig = hmac.new(SECRET.encode(), (ADMIN_USER + ":" + stamp).encode(), "sha256").hexdigest()
    return {"access_token": stamp + "." + sig, "expires_in": 28800}

@app.get("/api/admin/accounts", dependencies=[Depends(admin_auth)])
def list_accounts():
    with conn() as c:
        result = []
        for a in c.execute("SELECT id,username,max_devices,locked,key_active,created_at,note FROM accounts ORDER BY id DESC"):
            item = dict(a)
            item["devices"] = [dict(d) for d in c.execute(
                "SELECT device_id,device_label,locked,last_seen,session_hash IS NOT NULL AS session_active FROM devices WHERE account_id=? ORDER BY last_seen DESC",
                (a["id"],))]
            item["device_count"] = len(item["devices"])
            result.append(item)
        return result

@app.post("/api/admin/accounts", dependencies=[Depends(admin_auth)])
def create_account(data: CreateAccount):
    with conn() as c:
        try:
            c.execute("INSERT INTO accounts(username,password_hash,max_devices,created_at,note) VALUES(?,?,?,?,?)",
                      (data.username, hashpw(data.password), data.max_devices, int(time.time()), data.note.strip()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Tên tài khoản đã tồn tại.")
    return {"ok": True, "username": data.username}

@app.patch("/api/admin/accounts/{account_id}", dependencies=[Depends(admin_auth)])
def update_account(account_id: int, data: AccountUpdate):
    fields, values = [], []
    for key in ("max_devices", "locked", "key_active", "note"):
        value = getattr(data, key)
        if value is not None:
            fields.append(key + "=?")
            values.append(int(value) if key in ("locked", "key_active") else value)
    if not fields:
        raise HTTPException(400, "Không có thay đổi.")
    with conn() as c:
        cur = c.execute("UPDATE accounts SET " + ",".join(fields) + " WHERE id=?", (*values, account_id))
        if not cur.rowcount:
            raise HTTPException(404, "Không tìm thấy tài khoản.")
        if data.locked is True or data.key_active is False:
            c.execute("UPDATE devices SET session_hash=NULL WHERE account_id=?", (account_id,))
            c.execute("UPDATE accounts SET session_hash=NULL WHERE id=?", (account_id,))
    return {"ok": True}

@app.post("/api/admin/accounts/{account_id}/release-device", dependencies=[Depends(admin_auth)])
def release_all_devices(account_id: int):
    with conn() as c:
        if not c.execute("SELECT id FROM accounts WHERE id=?", (account_id,)).fetchone():
            raise HTTPException(404, "Không tìm thấy tài khoản.")
        c.execute("DELETE FROM devices WHERE account_id=?", (account_id,))
        c.execute("UPDATE accounts SET device_id=NULL,device_label=NULL,session_hash=NULL WHERE id=?", (account_id,))
    return {"ok": True}

@app.patch("/api/admin/accounts/{account_id}/devices/{device_id}", dependencies=[Depends(admin_auth)])
def update_device(account_id: int, device_id: str = Path(min_length=8, max_length=200), data: DeviceUpdate = ...):
    with conn() as c:
        cur = c.execute("UPDATE devices SET locked=?,session_hash=CASE WHEN ?=1 THEN NULL ELSE session_hash END WHERE account_id=? AND device_id=?",
                        (int(data.locked), int(data.locked), account_id, device_id))
        if not cur.rowcount:
            raise HTTPException(404, "Không tìm thấy thiết bị.")
    return {"ok": True}

@app.delete("/api/admin/accounts/{account_id}/devices/{device_id}", dependencies=[Depends(admin_auth)])
def release_one_device(account_id: int, device_id: str = Path(min_length=8, max_length=200)):
    with conn() as c:
        cur = c.execute("DELETE FROM devices WHERE account_id=? AND device_id=?", (account_id, device_id))
        if not cur.rowcount:
            raise HTTPException(404, "Không tìm thấy thiết bị.")
    return {"ok": True}

@app.post("/api/admin/accounts/{account_id}/reset-password", dependencies=[Depends(admin_auth)])
def reset_password(account_id: int, data: ResetPassword):
    with conn() as c:
        cur = c.execute("UPDATE accounts SET password_hash=?,session_hash=NULL WHERE id=?", (hashpw(data.password), account_id))
        if not cur.rowcount:
            raise HTTPException(404, "Không tìm thấy tài khoản.")
        c.execute("UPDATE devices SET session_hash=NULL WHERE account_id=?", (account_id,))
    return {"ok": True}

@app.get("/api/admin/settings", dependencies=[Depends(admin_auth)])
def get_settings():
    with conn() as c:
        return {r["key"]: r["value"] for r in c.execute("SELECT key,value FROM settings")}

@app.put("/api/admin/settings", dependencies=[Depends(admin_auth)])
def put_settings(values: dict):
    allowed = {"maintenance","maintenance_message","update_url","minimum_version","app_enabled","purchase_telegram","developer","publisher"}
    with conn() as c:
        for key, value in values.items():
            if key not in allowed:
                raise HTTPException(400, "Cài đặt không được hỗ trợ: " + key)
            if key in ("update_url","purchase_telegram") and value and not str(value).startswith("https://"):
                raise HTTPException(400, key + " phải dùng HTTPS")
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    return {"ok": True}

@app.get("/api/status")
def public_status():
    with conn() as c:
        return {"maintenance":setting(c,"maintenance") == "1",
                "maintenance_message":setting(c,"maintenance_message"),
                "app_enabled":setting(c,"app_enabled") == "1",
                "update_url":setting(c,"update_url"),
                "minimum_version":setting(c,"minimum_version"),
                "purchase_telegram":setting(c,"purchase_telegram"),
                "developer":setting(c,"developer"),
                "publisher":setting(c,"publisher")}

@app.post("/api/auth/login")
def login(data: LoginRequest):
    with conn() as c:
        require_available(c, data.app_version)
        row = c.execute("SELECT * FROM accounts WHERE username=?", (data.username,)).fetchone()
        if not row or not verify(data.password, row["password_hash"]):
            raise HTTPException(401, "Sai tài khoản hoặc mật khẩu.")
        if row["locked"]:
            raise HTTPException(403, "Tài khoản đã bị khóa. Vui lòng liên hệ nhà phát triển.")
        if not row["key_active"]:
            raise HTTPException(403, "Key đã bị dừng. Vui lòng liên hệ nhà phát triển.")
        existing = c.execute("SELECT * FROM devices WHERE account_id=? AND device_id=?", (row["id"], data.device_id)).fetchone()
        if existing and existing["locked"]:
            raise HTTPException(403, "Thiết bị này đã bị khóa bởi nhà phát hành.")
        count = c.execute("SELECT COUNT(*) AS n FROM devices WHERE account_id=?", (row["id"],)).fetchone()["n"]
        if not existing and count >= row["max_devices"]:
            raise HTTPException(409, "Tài khoản đã có chủ hoặc đã dùng đủ số thiết bị cho phép.")
        token, now = secrets.token_urlsafe(40), int(time.time())
        c.execute("INSERT INTO devices(account_id,device_id,device_label,session_hash,last_seen,locked) VALUES(?,?,?,?,?,0) "
                  "ON CONFLICT(account_id,device_id) DO UPDATE SET device_label=excluded.device_label,session_hash=excluded.session_hash,last_seen=excluded.last_seen",
                  (row["id"], data.device_id, data.device_label, session_hash(token), now))
        c.execute("UPDATE accounts SET device_id=?,device_label=?,session_hash=? WHERE id=?",
                  (data.device_id, data.device_label, session_hash(token), row["id"]))
        return {"ok":True,"session_token":token,"username":row["username"],"expires":"until-revoked","message":"Đăng nhập thành công."}

@app.post("/api/auth/validate")
def validate(data: ValidateRequest):
    with conn() as c:
        require_available(c, data.app_version)
        digest = session_hash(data.session_token)
        row = c.execute("SELECT a.id AS account_id,a.username,a.locked AS account_locked,a.key_active,d.locked AS device_locked "
                        "FROM devices d JOIN accounts a ON a.id=d.account_id WHERE d.device_id=? AND d.session_hash=?",
                        (data.device_id, digest)).fetchone()
        if not row or row["account_locked"] or not row["key_active"] or row["device_locked"]:
            raise HTTPException(401, "Phiên đăng nhập đã bị thu hồi hoặc thiết bị/key bị khóa. Vui lòng đăng nhập lại.")
        c.execute("UPDATE devices SET last_seen=? WHERE account_id=? AND device_id=?", (int(time.time()), row["account_id"], data.device_id))
        return {"ok":True,"username":row["username"],"app_enabled":True}

@app.post("/api/auth/logout")
def logout(data: ValidateRequest):
    digest = session_hash(data.session_token)
    with conn() as c:
        c.execute("UPDATE devices SET session_hash=NULL WHERE device_id=? AND session_hash=?", (data.device_id, digest))
        c.execute("UPDATE accounts SET session_hash=NULL WHERE device_id=? AND session_hash=?", (data.device_id, digest))
    return {"ok":True}

ADMIN_HTML = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phamquangios SEV</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b0c0f;color:#eee;font:15px system-ui}main{max-width:1050px;margin:auto;padding:22px}h1{color:#e6c27a}input,button{background:#191b20;color:#eee;border:1px solid #41434a;border-radius:10px;padding:11px;margin:4px 0;font:inherit}input{width:100%}button{cursor:pointer;background:#caa45d;color:#111;font-weight:700;border:0}section{border:1px solid #333;border-radius:16px;padding:15px;margin:15px 0;background:#101115}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.row{padding:12px 0;border-bottom:1px solid #303137;overflow-wrap:anywhere}.muted{color:#aaa;font-size:13px}.device{margin:8px 0 8px 12px;padding:10px;border-left:2px solid #6c624a;background:#15161a}.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.actions button{font-size:13px;padding:8px}.check{width:auto}@media(max-width:600px){main{padding:12px}.grid{grid-template-columns:1fr}}</style></head><body><main><h1>PHAMQUANG · SEV</h1><p class=muted>Quản lý tài khoản, thiết bị, key, bảo trì và cập nhật</p>
<section id=login><h2>Đăng nhập quản trị</h2><input id=au autocomplete=username placeholder="Tên admin"><input id=ap type=password autocomplete=current-password placeholder="Mật khẩu admin"><button onclick="login()">Đăng nhập</button><p id=msg></p></section>
<div id=panel hidden><section><h2>Tạo tài khoản</h2><div class=grid><input id=un placeholder="Tên tài khoản"><input id=pw type=password placeholder="Mật khẩu (ít nhất 8 ký tự)"><input id=md type=number min=1 max=100 value=1 placeholder="Số máy được phép"><input id=note placeholder="Ghi chú" maxlength=500></div><button onclick="create()">Tạo tài khoản</button><p class=muted>Không có đăng ký công khai; chỉ admin tạo tài khoản.</p></section>
<section><h2>Điều khiển ứng dụng</h2><label><input class=check id=maint type=checkbox> Bật bảo trì</label><label><input class=check id=enabled type=checkbox> Cho phép mở app</label><input id=mm placeholder="Thông báo bảo trì"><input id=upd placeholder="Link cập nhật HTTPS"><input id=ver placeholder="Phiên bản tối thiểu"><input id=tg placeholder="Link Telegram mua tài khoản"><button onclick="saveSettings()">Lưu cài đặt</button><p id=setmsg class=muted></p></section>
<section><h2>Tài khoản và thiết bị</h2><button onclick="loadAccounts()">Làm mới</button><input id=filter placeholder="Lọc tài khoản" oninput="renderAccounts()"><div id=accounts></div></section></div></main>
<script>
var token='', allAccounts=[];function $(id){return document.getElementById(id)}function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
async function api(p,o){o=o||{};var r=await fetch(p,{method:o.method||'GET',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:o.body});var d={};try{d=await r.json()}catch(e){}if(!r.ok)throw Error(d.detail||'Lỗi máy chủ');return d}
async function login(){try{var r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('au').value,password:$('ap').value})});var d=await r.json();if(!r.ok)throw Error(d.detail||'Đăng nhập thất bại');token=d.access_token;$('login').hidden=true;$('panel').hidden=false;await loadSettings();await loadAccounts()}catch(e){$('msg').textContent=e.message}}
async function create(){try{await api('/api/admin/accounts',{method:'POST',body:JSON.stringify({username:$('un').value.trim(),password:$('pw').value,max_devices:+$('md').value,note:$('note').value})});$('un').value='';$('pw').value='';$('note').value='';await loadAccounts();alert('Đã tạo tài khoản')}catch(e){alert(e.message)}}
async function loadAccounts(){try{allAccounts=await api('/api/admin/accounts');renderAccounts()}catch(e){alert(e.message)}}
function renderAccounts(){var q=$('filter').value.toLowerCase();$('accounts').innerHTML=allAccounts.filter(function(a){return a.username.toLowerCase().indexOf(q)>=0}).map(function(a){var devices=a.devices.map(function(d){return '<div class=device><b>'+esc(d.device_label||'iOS device')+'</b><br><span class=muted>'+esc(d.device_id)+' · '+new Date(d.last_seen*1000).toLocaleString()+' · '+(d.session_active?'đang đăng nhập':'đã đăng xuất')+'</span><br><b>'+ (d.locked?'MÁY BỊ KHÓA':'MÁY ĐƯỢC PHÉP')+'</b><div class=actions><button onclick="deviceLock('+a.id+',\\''+encodeURIComponent(d.device_id)+'\\','+(!d.locked)+')">'+(d.locked?'Mở khóa máy':'Khóa máy')+'</button><button onclick="releaseOne('+a.id+',\\''+encodeURIComponent(d.device_id)+'\\')">Gỡ máy</button></div></div>'}).join('');return '<div class=row><b>'+esc(a.username)+'</b> · '+(a.locked?'TÀI KHOẢN KHÓA':'TÀI KHOẢN MỞ')+' · '+(a.key_active?'KEY BẬT':'KEY DỪNG')+'<br><span class=muted>Máy: '+a.device_count+'/'+a.max_devices+' · '+esc(a.note||'')+'</span><div class=actions><button onclick="change('+a.id+',\\'locked\\','+(!a.locked)+')">'+(a.locked?'Mở khóa tài khoản':'Khóa tài khoản')+'</button><button onclick="change('+a.id+',\\'key_active\\','+(!a.key_active)+')">'+(a.key_active?'Dừng key':'Bật key')+'</button><button onclick="setMax('+a.id+','+a.max_devices+')">Đổi số máy</button><button onclick="resetPassword('+a.id+')">Đổi mật khẩu</button><button onclick="releaseAll('+a.id+')">Nhả tất cả máy</button></div>'+devices+'</div>'}).join('')||'<p class=muted>Không có tài khoản.</p>'}
async function change(id,k,v){try{await api('/api/admin/accounts/'+id,{method:'PATCH',body:JSON.stringify({[k]:v})});await loadAccounts()}catch(e){alert(e.message)}}
async function setMax(id,n){var v=prompt('Số máy (1–100)',n);if(v===null)return;n=Number(v);if(!Number.isInteger(n)||n<1||n>100){alert('Nhập số từ 1 đến 100');return}await change(id,'max_devices',n)}
async function resetPassword(id){var p=prompt('Mật khẩu mới (ít nhất 8 ký tự):');if(p===null)return;try{await api('/api/admin/accounts/'+id+'/reset-password',{method:'POST',body:JSON.stringify({password:p})});alert('Đã đổi mật khẩu và thu hồi phiên cũ');await loadAccounts()}catch(e){alert(e.message)}}
async function releaseAll(id){if(!confirm('Gỡ tất cả máy của tài khoản này?'))return;try{await api('/api/admin/accounts/'+id+'/release-device',{method:'POST'});await loadAccounts()}catch(e){alert(e.message)}}
async function deviceLock(id,d,v){try{await api('/api/admin/accounts/'+id+'/devices/'+d,{method:'PATCH',body:JSON.stringify({locked:v})});await loadAccounts()}catch(e){alert(e.message)}}
async function releaseOne(id,d){if(!confirm('Gỡ máy này?'))return;try{await api('/api/admin/accounts/'+id+'/devices/'+d,{method:'DELETE'});await loadAccounts()}catch(e){alert(e.message)}}
async function loadSettings(){var s=await api('/api/admin/settings');$('maint').checked=s.maintenance==='1';$('enabled').checked=s.app_enabled==='1';$('mm').value=s.maintenance_message||'';$('upd').value=s.update_url||'';$('ver').value=s.minimum_version||'1.0.0';$('tg').value=s.purchase_telegram||'https://t.me/phamquangioss'}
async function saveSettings(){try{await api('/api/admin/settings',{method:'PUT',body:JSON.stringify({maintenance:$('maint').checked?'1':'0',app_enabled:$('enabled').checked?'1':'0',maintenance_message:$('mm').value,update_url:$('upd').value,minimum_version:$('ver').value,purchase_telegram:$('tg').value})});$('setmsg').textContent='Đã lưu cài đặt'}catch(e){alert(e.message)}}
</script></body></html>'''

@app.get("/", response_class=HTMLResponse)
def admin_page():
    return ADMIN_HTML
