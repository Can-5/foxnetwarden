use foxnetwarden::collector::{live_connections, parse_process};

#[test]
fn test_parse_process_extracts_pid_and_name() {
    let (pid, name) = parse_process("users:((\"firefox\",pid=1234,fd=20))");
    assert_eq!(pid, Some(1234));
    assert_eq!(name, "firefox");

    let (pid, name) = parse_process("users:((\"systemd-resolve\",pid=42,fd=13))");
    assert_eq!(pid, Some(42));
    assert_eq!(name, "systemd-resolve");
}

#[test]
fn test_parse_process_missing_process_field() {
    let (pid, name) = parse_process("");
    assert_eq!(pid, None);
    assert_eq!(name, "?");

    let (pid, name) = parse_process("no users field here");
    assert_eq!(pid, None);
    assert_eq!(name, "?");
}

#[test]
fn test_live_connections_runs_without_panic() {
    let result = live_connections();
    assert!(result.is_ok(), "ss should run: {result:?}");
    for c in result.unwrap() {
        assert!(!c.local.is_empty(), "local address must be set");
        assert!(!c.state.is_empty(), "state must be set");
    }
}
