use foxnetwarden::collector::Connection;
use foxnetwarden::db::{
    db_insert_conn, history_query_conn, init_db_conn, top_talkers_conn, HistoryRow, Talker,
};

fn sample(pid: u32, name: &str, remote: &str) -> Connection {
    Connection {
        pid: Some(pid),
        name: name.to_string(),
        local: "192.168.1.103:50000".to_string(),
        remote: remote.to_string(),
        state: "ESTAB".to_string(),
        duration: 0,
    }
}

#[test]
fn test_db_insert_and_history_query() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    init_db_conn(&conn).unwrap();
    db_insert_conn(&conn, &sample(1, "firefox", "example.org:443")).unwrap();
    db_insert_conn(&conn, &sample(2, "curl", "api.github.com:443")).unwrap();

    let rows: Vec<HistoryRow> = history_query_conn(&conn).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r.remote.contains("example.org")));
    assert!(rows.iter().any(|r| r.name == "firefox"));
}

#[test]
fn test_db_top_talkers_ordered_by_count() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    init_db_conn(&conn).unwrap();
    db_insert_conn(&conn, &sample(1, "firefox", "a.example:443")).unwrap();
    db_insert_conn(&conn, &sample(1, "firefox", "b.example:443")).unwrap();
    db_insert_conn(&conn, &sample(2, "curl", "c.example:443")).unwrap();

    let talkers: Vec<Talker> = top_talkers_conn(&conn).unwrap();
    assert_eq!(talkers[0].name, "firefox");
    assert_eq!(talkers[0].count, 2);
    assert_eq!(talkers[1].name, "curl");
    assert_eq!(talkers[1].count, 1);
}
