pub const JOIN_COMMAND: &str = "join";
pub const JOIN_TOKEN_FLAG: &str = "--join-token";

pub fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

/// `nexguard join <token>` and `--join-token <token>` are the same thing; the
/// bare form is what the dashboard hands people to paste.
pub fn join_token(args: &[String]) -> Option<String> {
    if let Some(value) = arg_value(args, JOIN_TOKEN_FLAG).filter(|t| !t.is_empty()) {
        return Some(value);
    }
    let mut rest = args.iter().skip(1);
    if rest.next().map(String::as_str) != Some(JOIN_COMMAND) {
        return None;
    }
    rest.next().filter(|t| !t.is_empty() && !t.starts_with('-')).cloned()
}
