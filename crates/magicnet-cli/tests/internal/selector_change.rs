use super::*;
use crate::service;
use crate::test_support::{temp_app, TempApp};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const STORE: &str = ".config/magicnet/selector-selections.json";

#[derive(Clone, Copy)]
enum Behavior {
    Apply,
    Reject,
    Ignore,
    ConcurrentChoice,
}

struct ApiState {
    current: String,
    puts: usize,
    behavior: Behavior,
}

struct Fixture {
    app: App,
    _directory: TempApp,
    state: Arc<Mutex<ApiState>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(behavior: Behavior) -> Self {
        let directory = temp_app();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut app = App::for_test(directory.moddir.clone());
        app.api = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(ApiState {
            current: "old-node".into(),
            puts: 0,
            behavior,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let quitting = stop.clone();
        let worker = thread::spawn(move || {
            while !quitting.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept fixture request: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                if request.is_empty() {
                    continue;
                }
                let parts: Vec<_> = request.split_whitespace().collect();
                let mut size = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            size = value.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                assert!(size < 4096);
                let mut payload = vec![0; size];
                reader.read_exact(&mut payload).unwrap();
                drop(reader);
                let mut data = shared.lock().unwrap();
                let (status, body) = match (parts[0], parts[1]) {
                    ("GET", "/proxies/proxy") => (
                        200,
                        json!({
                            "type": "Selector", "now": data.current,
                            "all": ["old-node", "new-node", "user-choice"]
                        })
                        .to_string(),
                    ),
                    ("PUT", "/proxies/proxy") | ("PATCH", "/configs") => {
                        data.puts += 1;
                        let value: Value = serde_json::from_slice(&payload).unwrap();
                        match data.behavior {
                            Behavior::Apply => {
                                data.current = value
                                    [if parts[0] == "PATCH" { "mode" } else { "name" }]
                                .as_str()
                                .unwrap()
                                .into();
                                (204, String::new())
                            }
                            Behavior::Reject => (500, "{}".into()),
                            Behavior::Ignore => (204, String::new()),
                            Behavior::ConcurrentChoice => {
                                data.current = "user-choice".into();
                                (204, String::new())
                            }
                        }
                    }
                    ("GET", "/configs") => (200, json!({"mode":data.current}).to_string()),
                    ("DELETE", "/connections") => (204, String::new()),
                    ("GET", "/connections") => (200, "{\"connections\":[]}".into()),
                    _ => (404, "{}".into()),
                };
                drop(data);
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        Self {
            app,
            _directory: directory,
            state,
            stop,
            worker: Some(worker),
        }
    }

    fn stored(&self) -> Value {
        serde_json::from_slice(&fs::read(self.app.moddir.join(STORE)).unwrap()).unwrap()
    }

    fn change(&self) -> Result<SelectorChange, String> {
        let guard = service::config_apply_lock(&self.app).unwrap();
        change_selector_locked(&self.app, &guard, "proxy", "new-node", Some("old-node"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.app.api.trim_start_matches("http://"));
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn selector_change_commits_runtime_and_intent_and_preserves_other_groups() {
    let fixture = Fixture::new(Behavior::Apply);
    selector_store::set_checked(&fixture.app, "unrelated", Some("keep")).unwrap();
    let change = fixture.change().unwrap();
    assert_eq!(change.previous, "old-node");
    assert_eq!(change.previous_saved, None);
    assert_eq!(fixture.state.lock().unwrap().current, "new-node");
    assert_eq!(
        fixture.stored(),
        json!({"proxy":"new-node","unrelated":"keep"})
    );
    let guard = service::config_apply_lock(&fixture.app).unwrap();
    rollback_selector_locked(&fixture.app, &guard, &change).unwrap();
    assert_eq!(fixture.state.lock().unwrap().current, "old-node");
    assert_eq!(fixture.stored(), json!({"unrelated":"keep"}));
}

#[test]
fn selector_store_write_failure_is_fatal_before_runtime_put() {
    let fixture = Fixture::new(Behavior::Apply);
    selector_store::set_checked(&fixture.app, "proxy", Some("old-node")).unwrap();
    fs::remove_file(
        fixture
            .app
            .moddir
            .join(".config/magicnet/selector-selections.json.lock"),
    )
    .unwrap();
    fs::create_dir(
        fixture
            .app
            .moddir
            .join(".config/magicnet/selector-selections.json.lock"),
    )
    .unwrap();
    assert!(fixture.change().unwrap_err().contains("persist_failed"));
    assert_eq!(fixture.state.lock().unwrap().puts, 0);
    assert_eq!(fixture.state.lock().unwrap().current, "old-node");
    assert_eq!(fixture.stored()["proxy"], "old-node");
}

#[test]
fn selector_rejected_runtime_write_restores_absent_intent() {
    let fixture = Fixture::new(Behavior::Reject);
    selector_store::set_checked(&fixture.app, "unrelated", Some("keep")).unwrap();
    assert!(fixture.change().unwrap_err().contains("apply_failed"));
    assert_eq!(fixture.state.lock().unwrap().current, "old-node");
    assert_eq!(fixture.stored(), json!({"unrelated":"keep"}));
}

#[test]
fn selector_successful_http_without_applied_value_is_rejected() {
    let fixture = Fixture::new(Behavior::Ignore);
    selector_store::set_checked(&fixture.app, "proxy", Some("old-node")).unwrap();
    assert!(fixture.change().unwrap_err().contains("runtime_mismatch"));
    assert_eq!(fixture.state.lock().unwrap().current, "old-node");
    assert_eq!(fixture.stored()["proxy"], "old-node");
}

#[test]
fn selector_rollback_does_not_overwrite_external_new_choice() {
    let fixture = Fixture::new(Behavior::ConcurrentChoice);
    selector_store::set_checked(&fixture.app, "proxy", Some("old-node")).unwrap();
    let error = fixture.change().unwrap_err();
    assert!(error.starts_with("selector.rollback_failed;"));
    assert!(error.contains("rollback_runtime_conflict"));
    assert_eq!(fixture.state.lock().unwrap().current, "user-choice");
    assert_eq!(fixture.state.lock().unwrap().puts, 1);
    assert_eq!(fixture.stored()["proxy"], "old-node");
}

#[test]
fn selector_expected_value_and_member_checks_do_not_write() {
    let fixture = Fixture::new(Behavior::Apply);
    let guard = service::config_apply_lock(&fixture.app).unwrap();
    assert!(
        change_selector_locked(&fixture.app, &guard, "proxy", "new-node", Some("stale"))
            .unwrap_err()
            .contains("concurrent_change")
    );
    assert!(
        change_selector_locked(&fixture.app, &guard, "proxy", "not-allowed", None)
            .unwrap_err()
            .contains("member_not_allowed")
    );
    assert_eq!(fixture.state.lock().unwrap().puts, 0);
    assert!(!fixture.app.moddir.join(STORE).exists());
}

#[test]
fn selector_unknown_saved_intent_is_not_quarantined_or_replaced() {
    let fixture = Fixture::new(Behavior::Apply);
    let path = fixture.app.moddir.join(STORE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "unreadable intent").unwrap();
    assert!(fixture.change().unwrap_err().contains("store_unavailable"));
    assert_eq!(fs::read_to_string(path).unwrap(), "unreadable intent");
    assert_eq!(fixture.state.lock().unwrap().puts, 0);
}

#[test]
fn selector_manual_failure_invalidates_old_health_evidence_after_unlock() {
    let fixture = Fixture::new(Behavior::Ignore);
    assert!(crate::webui_api::select_proxy(&fixture.app, "proxy", "new-node").is_err());
    assert!(fixture
        .app
        .moddir
        .join(".state/connectivity-check.request")
        .is_file());
    assert!(service::try_config_apply_lock(&fixture.app)
        .unwrap()
        .is_some());
}

#[test]
fn selector_mode_write_is_verified_and_requests_fresh_health() {
    let fixture = Fixture::new(Behavior::Apply);
    fixture.state.lock().unwrap().current = "rule".into();
    crate::webui_api::set_clash_mode(&fixture.app, "direct").unwrap();
    assert_eq!(fixture.state.lock().unwrap().current, "direct");
    assert_eq!(fixture.state.lock().unwrap().puts, 1);
    assert!(fixture
        .app
        .moddir
        .join(".state/connectivity-check.request")
        .is_file());
    assert!(service::try_config_apply_lock(&fixture.app)
        .unwrap()
        .is_some());
}

#[test]
fn selector_mode_http_success_without_change_is_not_reported_as_success() {
    let fixture = Fixture::new(Behavior::Ignore);
    fixture.state.lock().unwrap().current = "rule".into();
    assert_eq!(
        crate::webui_api::set_clash_mode(&fixture.app, "direct").unwrap_err(),
        "mode.runtime_mismatch"
    );
    assert_eq!(fixture.state.lock().unwrap().current, "rule");
    assert!(fixture
        .app
        .moddir
        .join(".state/connectivity-check.request")
        .is_file());
    assert!(service::try_config_apply_lock(&fixture.app)
        .unwrap()
        .is_some());
}
