import os
import hmac
import json
import time
import base64
import hashlib
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from psycopg_pool import ConnectionPool
import psycopg
from psycopg.rows import dict_row

# Read the project's .env without requiring an additional package.
def load_env():
    env_path = Path(__file__).with_name(".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

load_env()

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "1030hackthon")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-development-secret")
COOKIE_NAME = "submission_session"

conninfo = (
    f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} "
    f"user={DB_USER} password={DB_PASSWORD}"
)
pool = ConnectionPool(conninfo=conninfo, min_size=1, max_size=5, kwargs={"row_factory": dict_row})

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt + digest).decode("ascii")

def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.encode("ascii"))
        salt, expected = raw[:16], raw[16:]
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def make_session(user: dict) -> str:
    payload = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "exp": int(time.time()) + 60 * 60 * 12,
    }
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return raw + "." + sig

def read_session(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token or "." not in token:
        return None
    raw, sig = token.rsplit(".", 1)
    expected = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if payload["exp"] < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def current_user(request: Request, role: Optional[str] = None):
    user = read_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="請先登入")
    if role and user["role"] != role:
        raise HTTPException(status_code=403, detail="沒有此操作的權限")
    return user

def init_db():
    with pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(10) NOT NULL CHECK (role IN ('author', 'editor')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                submission_id SERIAL PRIMARY KEY,
                author_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                category VARCHAR(100) NOT NULL,
                title VARCHAR(200) NOT NULL,
                content TEXT NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT '編輯中'
                    CHECK (status IN ('編輯中', '審查中', '已通過')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status)")
        # Create the first editor account from .env, if configured.
        editor_name = os.getenv("EDITOR_USERNAME")
        editor_password = os.getenv("EDITOR_PASSWORD")
        if editor_name and editor_password:
            existing = conn.execute(
                "SELECT user_id FROM users WHERE username=%s", (editor_name,)
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'editor')",
                    (editor_name, hash_password(editor_password))
                )
        conn.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    pool.close()

app = FastAPI(title="稿件投稿與審查系統", lifespan=lifespan)

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.post("/api/register")
async def register(request: Request):
    data = await request.json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if len(username) < 3 or len(password) < 8:
        raise HTTPException(400, "帳號至少 3 個字元，密碼至少 8 個字元")
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'author') RETURNING user_id, username, role",
                (username, hash_password(password))
            ).fetchone()
            conn.commit()
        response = JSONResponse({"message": "註冊成功", "user": row})
        response.set_cookie(COOKIE_NAME, make_session(row), httponly=True, samesite="lax", max_age=43200)
        return response
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "此帳號已存在")

@app.post("/api/login")
async def login(request: Request):
    data = await request.json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    with pool.connection() as conn:
        user = conn.execute(
            "SELECT user_id, username, password_hash, role FROM users WHERE username=%s",
            (username,)
        ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(401, "帳號或密碼錯誤")
    public_user = {k: user[k] for k in ("user_id", "username", "role")}
    response = JSONResponse({"message": "登入成功", "user": public_user})
    response.set_cookie(COOKIE_NAME, make_session(public_user), httponly=True, samesite="lax", max_age=43200)
    return response

@app.post("/api/logout")
def logout():
    response = JSONResponse({"message": "已登出"})
    response.delete_cookie(COOKIE_NAME)
    return response

@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    return {"user_id": user["user_id"], "username": user["username"], "role": user["role"]}

@app.get("/api/submissions")
def list_submissions(request: Request):
    user = current_user(request)
    with pool.connection() as conn:
        if user["role"] == "author":
            rows = conn.execute(
                """SELECT submission_id, category, title, status, updated_at
                   FROM submissions WHERE author_id=%s ORDER BY updated_at DESC""",
                (user["user_id"],)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT s.submission_id, u.username AS author, s.category, s.title, s.status, s.updated_at
                   FROM submissions s JOIN users u ON s.author_id=u.user_id
                   WHERE s.status='審查中' ORDER BY s.updated_at ASC"""
            ).fetchall()
    return rows

@app.post("/api/submissions")
async def create_submission(request: Request):
    user = current_user(request, "author")
    data = await request.json()
    category, title, content = [str(data.get(k, "")).strip() for k in ("category", "title", "content")]
    if not category or not title or not content:
        raise HTTPException(400, "類別、標題及文章內容皆為必填")
    with pool.connection() as conn:
        row = conn.execute(
            """INSERT INTO submissions (author_id, category, title, content)
               VALUES (%s, %s, %s, %s)
               RETURNING submission_id""",
            (user["user_id"], category, title, content)
        ).fetchone()
        conn.commit()
    return {"message": "新增成功", "submission_id": row["submission_id"]}

@app.get("/api/submissions/{submission_id}")
def get_submission(submission_id: int, request: Request):
    user = current_user(request)
    with pool.connection() as conn:
        row = conn.execute(
            """SELECT s.submission_id, s.author_id, u.username AS author, s.category,
                      s.title, s.content, s.status, s.created_at, s.updated_at
               FROM submissions s JOIN users u ON s.author_id=u.user_id
               WHERE s.submission_id=%s""",
            (submission_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "找不到稿件")
    if user["role"] == "author" and row["author_id"] != user["user_id"]:
        raise HTTPException(403, "只能查看自己的稿件")
    if user["role"] == "editor" and row["status"] != "審查中":
        raise HTTPException(403, "只能查看審查中的稿件")
    return row

@app.put("/api/submissions/{submission_id}")
async def update_submission(submission_id: int, request: Request):
    user = current_user(request, "author")
    data = await request.json()
    category, title, content = [str(data.get(k, "")).strip() for k in ("category", "title", "content")]
    if not category or not title or not content:
        raise HTTPException(400, "類別、標題及文章內容皆為必填")
    with pool.connection() as conn:
        cur = conn.execute(
            """UPDATE submissions SET category=%s, title=%s, content=%s, updated_at=NOW()
               WHERE submission_id=%s AND author_id=%s AND status='編輯中'""",
            (category, title, content, submission_id, user["user_id"])
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(400, "稿件不存在，或目前狀態不能編輯")
    return {"message": "修改成功"}

@app.delete("/api/submissions/{submission_id}")
def delete_submission(submission_id: int, request: Request):
    user = current_user(request, "author")
    with pool.connection() as conn:
        cur = conn.execute(
            "DELETE FROM submissions WHERE submission_id=%s AND author_id=%s AND status='編輯中'",
            (submission_id, user["user_id"])
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(400, "稿件不存在，或只有編輯中的稿件可以刪除")
    return {"message": "刪除成功"}

@app.post("/api/submissions/{submission_id}/submit")
def submit_submission(submission_id: int, request: Request):
    user = current_user(request, "author")
    with pool.connection() as conn:
        cur = conn.execute(
            """UPDATE submissions SET status='審查中', updated_at=NOW()
               WHERE submission_id=%s AND author_id=%s AND status='編輯中'""",
            (submission_id, user["user_id"])
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(400, "只有自己的編輯中稿件可以送出")
    return {"message": "投稿已送出"}

@app.post("/api/submissions/{submission_id}/approve")
def approve_submission(submission_id: int, request: Request):
    current_user(request, "editor")
    with pool.connection() as conn:
        cur = conn.execute(
            """UPDATE submissions SET status='已通過', updated_at=NOW()
               WHERE submission_id=%s AND status='審查中'""",
            (submission_id,)
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(400, "找不到審查中的稿件")
    return {"message": "已通過稿件"}

@app.post("/api/submissions/{submission_id}/return")
async def return_submission(submission_id: int, request: Request):
    current_user(request, "editor")
    data = await request.json()
    comment = str(data.get("comment", "")).strip()
    with pool.connection() as conn:
        cur = conn.execute(
            """UPDATE submissions SET status='編輯中', updated_at=NOW()
               WHERE submission_id=%s AND status='審查中'""",
            (submission_id,)
        )
        if cur.rowcount:
            # Optional review note, stored as a simple notice in the response only in this starter version.
            conn.commit()
        else:
            conn.rollback()
            raise HTTPException(400, "找不到審查中的稿件")
    return {"message": "稿件已退回作者修改", "comment": comment}

HTML = r"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>稿件投稿與審查系統</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#202938;font-family:Arial,"Noto Sans TC",sans-serif}
header{background:#23395d;color:white;padding:20px 5%;display:flex;justify-content:space-between;align-items:center}
main{max-width:1050px;margin:28px auto;padding:0 18px}.panel{background:white;border-radius:12px;padding:22px;margin-bottom:18px;box-shadow:0 2px 12px #17255412}
h1{font-size:21px;margin:0}h2{font-size:19px;margin:0 0 16px}.muted{color:#667085;font-size:14px}
input,select,textarea{width:100%;padding:11px;border:1px solid #ccd3df;border-radius:7px;margin:6px 0 14px;font:inherit}
textarea{min-height:180px;resize:vertical}button{border:0;border-radius:7px;padding:10px 15px;background:#315b9a;color:white;cursor:pointer;margin:3px}
button.secondary{background:#e8edf5;color:#23395d}button.danger{background:#b93838}button.good{background:#28784c}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #e8ebf0}th{color:#667085;font-size:13px}
.status{display:inline-block;padding:4px 9px;border-radius:20px;background:#edf1f7;font-size:12px}.review{background:#fff2d8}.approved{background:#dff4e7}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.hidden{display:none}.actions{white-space:nowrap}
@media(max-width:650px){.grid{grid-template-columns:1fr}table{font-size:13px}th,td{padding:9px 5px}.actions{white-space:normal}}
</style></head>
<body>
<header><h1>稿件投稿與審查系統</h1><div id="userbar"></div></header>
<main>
<section id="auth" class="panel">
<h2>登入系統</h2><div class="grid"><div><label>帳號</label><input id="loginUser" autocomplete="username"></div><div><label>密碼</label><input id="loginPass" type="password" autocomplete="current-password"></div></div>
<button onclick="login()">登入</button><button class="secondary" onclick="register()">註冊作者帳號</button><p class="muted">作者可自行註冊；編輯帳號由系統管理者透過 .env 設定。</p>
</section>
<section id="workspace" class="hidden">
<div id="authorArea" class="hidden">
<div class="panel"><h2 id="formTitle">新增投稿</h2><input type="hidden" id="submissionId">
<label>類別</label><input id="category" placeholder="例如：資訊科技">
<label>標題</label><input id="title" placeholder="請輸入稿件標題">
<label>文章內容</label><textarea id="content" placeholder="請輸入文章內容"></textarea>
<button onclick="saveDraft()">儲存稿件</button><button class="secondary" onclick="clearForm()">清空</button></div>
<div class="panel"><h2>我的投稿清單</h2><div id="authorList"></div></div>
</div>
<div id="editorArea" class="hidden"><div class="panel"><h2>待審查稿件</h2><div id="editorList"></div></div><div id="reviewPanel" class="panel hidden"></div></div>
</section>
</main>
<script>
const $=id=>document.getElementById(id);
async function api(url,method="GET",data=null){const opt={method,headers:{}};if(data!==null){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(data)}
 const r=await fetch(url,opt);let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.detail||"操作失敗");return d}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function login(){try{await api("/api/login","POST",{username:$("loginUser").value,password:$("loginPass").value});await start()}catch(e){alert(e.message)}}
async function register(){try{await api("/api/register","POST",{username:$("loginUser").value,password:$("loginPass").value});await start()}catch(e){alert(e.message)}}
async function logout(){await api("/api/logout","POST");location.reload()}
async function start(){try{const u=await api("/api/me");$("auth").classList.add("hidden");$("workspace").classList.remove("hidden");$("userbar").innerHTML=`${esc(u.username)}（${u.role==="author"?"作者":"編輯"}） <button class="secondary" onclick="logout()">登出</button>`;
 if(u.role==="author"){$("authorArea").classList.remove("hidden");$("editorArea").classList.add("hidden");await loadAuthor()}else{$("editorArea").classList.remove("hidden");$("authorArea").classList.add("hidden");await loadEditor()}}catch(e){$("auth").classList.remove("hidden")}}
function clearForm(){$("submissionId").value="";$("category").value="";$("title").value="";$("content").value="";$("formTitle").textContent="新增投稿"}
async function saveDraft(){const data={category:$("category").value,title:$("title").value,content:$("content").value};try{const id=$("submissionId").value;if(id)await api("/api/submissions/"+id,"PUT",data);else await api("/api/submissions","POST",data);clearForm();await loadAuthor();alert("已儲存")}catch(e){alert(e.message)}}
async function loadAuthor(){const rows=await api("/api/submissions");$("authorList").innerHTML=rows.length?`<table><thead><tr><th>類別</th><th>標題</th><th>審查狀態</th><th>操作</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.category)}</td><td>${esc(r.title)}</td><td><span class="status ${r.status==="審查中"?"review":r.status==="已通過"?"approved":""}">${esc(r.status)}</span></td><td class="actions">${r.status==="編輯中"?`<button class="secondary" onclick="editDraft(${r.submission_id})">編輯</button><button onclick="submitDraft(${r.submission_id})">送出</button><button class="danger" onclick="deleteDraft(${r.submission_id})">刪除</button>`:"—"}</td></tr>`).join("")}</tbody></table>`:"<p class='muted'>目前沒有投稿稿件。</p>"}
async function editDraft(id){try{const r=await api("/api/submissions/"+id);$("submissionId").value=id;$("category").value=r.category;$("title").value=r.title;$("content").value=r.content;$("formTitle").textContent="編輯投稿";window.scrollTo({top:0,behavior:"smooth"})}catch(e){alert(e.message)}}
async function submitDraft(id){if(!confirm("確定送出審查？送出後將不能自行編輯。"))return;try{await api(`/api/submissions/${id}/submit`,"POST");await loadAuthor()}catch(e){alert(e.message)}}
async function deleteDraft(id){if(!confirm("確定刪除此稿件？"))return;try{await api("/api/submissions/"+id,"DELETE");await loadAuthor()}catch(e){alert(e.message)}}
async function loadEditor(){const rows=await api("/api/submissions");$("editorList").innerHTML=rows.length?`<table><thead><tr><th>作者</th><th>類別</th><th>標題</th><th>操作</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.author)}</td><td>${esc(r.category)}</td><td>${esc(r.title)}</td><td><button onclick="review(${r.submission_id})">查看／審查</button></td></tr>`).join("")}</tbody></table>`:"<p class='muted'>目前沒有待審查稿件。</p>"}
async function review(id){try{const r=await api("/api/submissions/"+id);$("reviewPanel").classList.remove("hidden");$("reviewPanel").innerHTML=`<h2>稿件內容</h2><p><b>作者：</b>${esc(r.author)}　<b>類別：</b>${esc(r.category)}</p><h3>${esc(r.title)}</h3><div style="white-space:pre-wrap;line-height:1.8">${esc(r.content)}</div><hr><label>退回原因／修改意見（選填）</label><textarea id="reviewComment" style="min-height:90px"></textarea><button class="good" onclick="approve(${id})">審查通過</button><button class="danger" onclick="returnDraft(${id})">退回作者修改</button>`;$("reviewPanel").scrollIntoView({behavior:"smooth"})}catch(e){alert(e.message)}}
async function approve(id){if(!confirm("確定通過此稿件？"))return;try{await api(`/api/submissions/${id}/approve`,"POST");$("reviewPanel").classList.add("hidden");await loadEditor()}catch(e){alert(e.message)}}
async function returnDraft(id){try{await api(`/api/submissions/${id}/return`,"POST",{comment:$("reviewComment").value});$("reviewPanel").classList.add("hidden");await loadEditor();alert("已退回作者修改")}catch(e){alert(e.message)}}
start();
</script></body></html>"""
