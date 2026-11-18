//! SQLite bağlantı geçmişi, kurallar ve ayarlar. Veri uygulama veri dizininde tutulur.

use crate::collector::Connection;
use rusqlite::{params, Connection as SqliteConn};
use serde::Serialize;
use std::path::PathBuf;

/// Tek bir geçmiş satırı (UI tablosu ve Tauri komutu için).
#[derive(Debug, Clone, Serialize)]
pub struct HistoryRow {
    pub id: i64,
    pub pid: Option<i64>,
    pub name: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub ts: String,
}

/// Süreç bazlı hedef özeti (Analiz ekranı).
#[derive(Debug, Clone, Serialize)]
pub struct Talker {
    pub name: String,
    pub count: i64,
}

/// Şema oluşturur (idempotent).
pub fn init_db_conn(conn: &SqliteConn) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS connections (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      TEXT NOT NULL DEFAULT (datetime('now')),
            pid     INTEGER,
            name    TEXT NOT NULL,
            local   TEXT NOT NULL,
            remote  TEXT NOT NULL,
            state   TEXT NOT NULL
        );",
    )
    .map_err(|e| format!("init_db: {e}"))
}

/// Uygulama veri dizinindeki SQLite dosyasının yolu.
pub fn db_path() -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "veri dizini bulunamadı".to_string())?
        .join("foxnetwarden");
    std::fs::create_dir_all(&dir).map_err(|e| format!("db dir: {e}"))?;
    Ok(dir.join("history.db"))
}

/// Uygulama veri dizininde yeni bir bağlantı açar ve şemayı hazırlar.
pub fn open_db() -> Result<SqliteConn, String> {
    let conn = SqliteConn::open(db_path()?).map_err(|e| format!("db open: {e}"))?;
    init_db_conn(&conn)?;
    Ok(conn)
}

/// Bir gözlemi geçmişe yazar (verilen bağlantı üzerinden).
pub fn db_insert_conn(conn: &SqliteConn, c: &Connection) -> Result<(), String> {
    conn.execute(
        "INSERT INTO connections (pid, name, local, remote, state) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![c.pid, c.name, c.local, c.remote, c.state],
    )
    .map_err(|e| format!("db_insert: {e}"))?;
    Ok(())
}

/// Uygulama veri dizinindeki DB'ye yazar.
pub fn db_insert(c: &Connection) -> Result<(), String> {
    let conn = open_db()?;
    db_insert_conn(&conn, c)
}

/// Geçmiş satırlarını en yeniden eskiye doğru döndürür (verilen bağlantı üzerinden).
pub fn history_query_conn(conn: &SqliteConn) -> Result<Vec<HistoryRow>, String> {
    let mut stmt = conn
        .prepare("SELECT id, pid, name, local, remote, state, ts FROM connections ORDER BY id DESC")
        .map_err(|e| format!("history prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(HistoryRow {
                id: r.get(0)?,
                pid: r.get(1)?,
                name: r.get(2)?,
                local: r.get(3)?,
                remote: r.get(4)?,
                state: r.get(5)?,
                ts: r.get(6)?,
            })
        })
        .map_err(|e| format!("history query: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("history row: {e}"))?);
    }
    Ok(out)
}

/// Uygulama DB'sinden geçmiş sorgular.
pub fn history_query() -> Result<Vec<HistoryRow>, String> {
    let conn = open_db()?;
    history_query_conn(&conn)
}

/// En çok hedefe bağlanan süreçleri sıralar (verilen bağlantı üzerinden).
pub fn top_talkers_conn(conn: &SqliteConn) -> Result<Vec<Talker>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT name, COUNT(DISTINCT remote) AS cnt FROM connections \
             GROUP BY name ORDER BY cnt DESC, name ASC LIMIT 20",
        )
        .map_err(|e| format!("top_talkers prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Talker {
                name: r.get(0)?,
                count: r.get(1)?,
            })
        })
        .map_err(|e| format!("top_talkers query: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("top_talkers row: {e}"))?);
    }
    Ok(out)
}

/// Uygulama DB'sinden top-talker listesi.
pub fn top_talkers() -> Result<Vec<Talker>, String> {
    let conn = open_db()?;
    top_talkers_conn(&conn)
}
