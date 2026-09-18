use nexguard_core::session;
use serde_json::Value;

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).expect("the core answers in JSON")
}

#[test]
fn an_api_base_becomes_the_host_the_client_dials() {
    for (base, want) in [
        ("https://api.nexguard.sh", "api.nexguard.sh"),
        ("http://api.nexguard.sh/", "api.nexguard.sh"),
        ("api.nexguard.sh", "api.nexguard.sh"),
        ("https://api.nexguard.sh/api/v1", "api.nexguard.sh"),
        ("  https://staging.nexguard.sh  ", "staging.nexguard.sh"),
    ] {
        assert_eq!(session::api_host(base).as_deref(), Some(want), "base {:?}", base);
    }
    for empty in ["", "   ", "https://", "http:///path"] {
        assert_eq!(session::api_host(empty), None, "base {:?}", empty);
    }
}

#[test]
fn the_last_failure_is_held_until_the_next_attempt_and_cleared_when_the_host_stops() {
    let answer = parsed(&session::prepare(r#"{"api_base":"https://api.nexguard.sh"}"#));
    assert_eq!(answer["ok"], Value::Bool(false));
    assert!(
        answer["error"].as_str().unwrap_or_default().contains("signed in"),
        "unhelpful error: {}",
        answer["error"]
    );

    let failed = parsed(&session::status());
    assert_eq!(failed["state"], Value::String("error".to_owned()));
    assert!(!failed["error"].as_str().unwrap_or_default().is_empty());

    session::stop();
    let idle = parsed(&session::status());
    assert_eq!(idle["state"], Value::String("disconnected".to_owned()));
    assert_eq!(idle["error"], Value::Null);
    assert_eq!(idle["peers"].as_array().map(Vec::len), Some(0));

    let malformed = parsed(&session::prepare("not json"));
    assert_eq!(malformed["ok"], Value::Bool(false));
    assert!(!malformed["error"].as_str().unwrap_or_default().is_empty());
    session::stop();
}
