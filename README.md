# 稿件投稿與審查系統

依照課堂作業的環境製作：FastAPI + PostgreSQL + psycopg 3。

## 1. 放置檔案
將 `main.py` 放進你的 `1030what` 專案資料夾。把 `.env.example` 複製並改名為 `.env`，再填入自己的資料庫密碼與編輯帳號密碼。

## 2. 安裝套件
在 `1030what` 終端機執行：

```bash
uv pip install fastapi psycopg psycopg-pool
```

## 3. 建立資料庫
依照課堂講義，在 Adminer 建立 PostgreSQL 資料庫 `1030hackthon`。
程式啟動時會自動建立 `users`、`submissions` 兩張資料表。

## 4. 啟動
```bash
uv run fastapi dev main.py
```
瀏覽器開啟 http://127.0.0.1:8000

## 5. 使用方式
- 作者：在登入頁輸入新帳號及至少 8 碼密碼，按「註冊作者帳號」即可建立作者帳號。
- 編輯：第一次啟動時，程式會依 `.env` 的 `EDITOR_USERNAME` / `EDITOR_PASSWORD` 建立編輯帳號。
- 作者只能修改、刪除編輯中的稿件。
- 作者送出後狀態變成「審查中」。
- 編輯通過後狀態變成「已通過」；退回後回到「編輯中」。

## 注意
這是課堂作業用的起始版本。正式部署前應更換 `SECRET_KEY`、使用 HTTPS、加入 CSRF 防護、限制登入嘗試，並把退回原因存入資料表（目前介面可輸入退回原因，但此版本尚未永久保存）。
