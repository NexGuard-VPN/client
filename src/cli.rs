pub const JOIN_COMMAND: &str = "join";
pub const JOIN_TOKEN_FLAG: &str = "--join-token";
pub const MESH_FLAG: &str = "--mesh";
pub const DAEMON_FLAG: &str = "--daemon";

const SERVICE_FLAGS: [&str; 2] = ["--share-internet", "--magic-dns"];
const SERVICE_OPTIONS: [(&str, Option<&str>); 5] = [
    ("--network", None),
    ("--exit-node", None),
    ("--advertise-routes", None),
    ("--token", Some("-t")),
    ("--name", Some("-n")),
];

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

/// What the boot service runs. With `--mesh` or a join token it is the headless
/// node that connects at boot; otherwise it is the idle daemon a desktop app
/// drives. A join token is redeemed once, in the foreground, before the service
/// is written; the unit file is world-readable, so the secret never goes in it.
pub fn service_args(args: &[String]) -> Vec<String> {
    let headless = args.iter().any(|a| a == MESH_FLAG) || join_token(args).is_some();
    if !headless {
        return vec![DAEMON_FLAG.to_string()];
    }
    let mut out = vec![MESH_FLAG.to_string()];
    for flag in SERVICE_FLAGS {
        if args.iter().any(|a| a == flag) {
            out.push(flag.to_string());
        }
    }
    for (long, short) in SERVICE_OPTIONS {
        let value = arg_value(args, long).or_else(|| short.and_then(|s| arg_value(args, s)));
        if let Some(value) = value {
            out.push(long.to_string());
            out.push(value);
        }
    }
    out
}
