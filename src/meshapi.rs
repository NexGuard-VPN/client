use crate::api::{api_host, http_tls_request, TlsRequest, DEFAULT_READ_TIMEOUT};
pub use crate::meshtypes::*;

const ENROLL_PATH: &str = "/api/mesh/enroll";
const NETMAP_PATH: &str = "/api/mesh/netmap";
const ENDPOINTS_PATH: &str = "/api/mesh/endpoints";
const DEVICES_PATH: &str = "/api/mesh/devices";
const INVITES_PATH: &str = "/api/mesh/invites";
const NETWORKS_PATH: &str = "/api/mesh/networks";
const MEMBERS_PATH: &str = "/api/mesh/members";
const PROJECTS_PATH: &str = "/api/projects";
const JOIN_TOKENS_SUFFIX: &str = "/join-tokens";
pub const IDENTITY_FILE: &str = "mesh.json";
const NETMAP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

pub fn enroll(user_token: &str, req: &EnrollRequest) -> Result<MeshIdentity, String> {
    let body = serde_json::to_string(req).map_err(|e| format!("encode enroll: {}", e))?;
    // A join token authenticates the request on its own, so the machine needs
    // no account credential of its own.
    let auth = if req.join_token.is_some() { None } else { Some(user_token) };
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: ENROLL_PATH,
            body: Some(&body),
            auth,
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(enroll_error(status, &resp));
    }
    let mut identity: MeshIdentity =
        serde_json::from_str(&resp).map_err(|e| format!("parse enroll: {} — {}", e, resp))?;
    identity.public_key = req.public_key.clone();
    Ok(identity)
}

pub fn netmap(token: &str, since: u64) -> Result<NetMap, String> {
    let path = format!("{}?since={}", NETMAP_PATH, since);
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "GET",
            path: &path,
            body: None,
            auth: Some(token),
            read_timeout: NETMAP_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(format!("netmap: HTTP {} — {}", status, resp));
    }
    serde_json::from_str(&resp).map_err(|e| format!("parse netmap: {} — {}", e, resp))
}

pub fn accept_invite(user_token: &str, invite: &str) -> Result<AcceptedInvite, String> {
    let path = format!("{}/{}/accept", INVITES_PATH, invite.trim());
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: &path,
            body: Some("{}"),
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(invite_error(status, &resp));
    }
    serde_json::from_str(&resp).map_err(|e| format!("parse invite: {} — {}", e, resp))
}

pub fn list_projects(user_token: &str) -> Result<Vec<Project>, String> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        projects: Vec<Project>,
    }
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "GET",
            path: PROJECTS_PATH,
            body: None,
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(format!("list projects: HTTP {} — {}", status, resp));
    }
    serde_json::from_str::<Resp>(&resp)
        .map(|r| r.projects)
        .map_err(|e| format!("parse projects: {} — {}", e, resp))
}

pub fn create_project(user_token: &str, name: &str) -> Result<Project, String> {
    let body = serde_json::json!({ "name": name }).to_string();
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: PROJECTS_PATH,
            body: Some(&body),
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    match status {
        200 | 201 => serde_json::from_str(&resp)
            .map_err(|e| format!("parse project: {} — {}", e, resp)),
        402 => Err("Your plan does not include this.".to_string()),
        _ => Err(format!("create project: HTTP {} — {}", status, resp)),
    }
}

/// Mints a join token for a project. The secret comes back once, which is why
/// the caller shows it immediately rather than storing it.
pub fn create_join_token(user_token: &str, project_id: &str) -> Result<JoinToken, String> {
    let path = format!("{}/{}{}", PROJECTS_PATH, project_id, JOIN_TOKENS_SUFFIX);
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: &path,
            body: Some("{}"),
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    match status {
        200 | 201 => {
            serde_json::from_str(&resp).map_err(|e| format!("parse join token: {} — {}", e, resp))
        }
        403 => Err("Only a project admin can add a machine.".to_string()),
        _ => Err(format!("join token: HTTP {} — {}", status, resp)),
    }
}

pub fn networks(user_token: &str) -> Result<Vec<MeshNetworkSummary>, String> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        networks: Vec<MeshNetworkSummary>,
    }
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "GET",
            path: NETWORKS_PATH,
            body: None,
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(format!("list networks: HTTP {} — {}", status, resp));
    }
    serde_json::from_str::<Resp>(&resp)
        .map(|r| r.networks)
        .map_err(|e| format!("parse networks: {} — {}", e, resp))
}

pub fn create_invite(user_token: &str, req: &InviteRequest) -> Result<MeshInvite, String> {
    let body = serde_json::to_string(req).map_err(|e| format!("encode invite: {}", e))?;
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: INVITES_PATH,
            body: Some(&body),
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    match status {
        200 | 201 => serde_json::from_str(&resp)
            .map_err(|e| format!("parse invite: {} — {}", e, resp)),
        409 => Err("That person is already a member of this network.".to_string()),
        402 => Err("Your plan does not include team members.".to_string()),
        _ => Err(format!("Could not send the invite: HTTP {} — {}", status, resp)),
    }
}

pub fn list_devices(user_token: &str) -> Result<Vec<MeshDeviceView>, String> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        devices: Vec<MeshDeviceView>,
    }
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "GET",
            path: DEVICES_PATH,
            body: None,
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(format!("list devices: HTTP {} — {}", status, resp));
    }
    serde_json::from_str::<Resp>(&resp)
        .map(|r| r.devices)
        .map_err(|e| format!("parse devices: {} — {}", e, resp))
}

pub fn list_members(user_token: &str) -> Result<Vec<MeshMember>, String> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        members: Vec<MeshMember>,
    }
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "GET",
            path: MEMBERS_PATH,
            body: None,
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if status != 200 {
        return Err(format!("list members: HTTP {} — {}", status, resp));
    }
    serde_json::from_str::<Resp>(&resp)
        .map(|r| r.members)
        .map_err(|e| format!("parse members: {} — {}", e, resp))
}

pub fn revoke_member(user_token: &str, member_id: &str) -> Result<(), String> {
    let path = format!("{}/{}", MEMBERS_PATH, member_id);
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "DELETE",
            path: &path,
            body: None,
            auth: Some(user_token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("remove member: HTTP {} — {}", status, resp))
    }
}

fn invite_error(status: u16, body: &str) -> String {
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    match (status, code.as_str()) {
        (404, _) => "That invite link is not valid, or it has already been used.".to_string(),
        (410, _) => "That invite has expired. Ask for a new link.".to_string(),
        (403, "invite_email_mismatch") => {
            "This invite was sent to a different email address.".to_string()
        }
        (401, _) | (403, _) => "Sign in to accept this invite.".to_string(),
        _ => format!("Could not accept the invite: HTTP {} — {}", status, body),
    }
}

pub fn report_endpoints(token: &str, endpoints: &[String]) -> Result<(), String> {
    let body = serde_json::json!({ "endpoints": endpoints }).to_string();
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "POST",
            path: ENDPOINTS_PATH,
            body: Some(&body),
            auth: Some(token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("report endpoints: HTTP {} — {}", status, resp))
    }
}

pub fn update_device(token: &str, device_id: &str, patch: &DevicePatch) -> Result<(), String> {
    let body = serde_json::to_string(patch).map_err(|e| format!("encode patch: {}", e))?;
    let path = format!("{}/{}", DEVICES_PATH, device_id);
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "PATCH",
            path: &path,
            body: Some(&body),
            auth: Some(token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("update device: HTTP {} — {}", status, resp))
    }
}

pub fn leave(token: &str, device_id: &str) -> Result<(), String> {
    let path = format!("{}/{}", DEVICES_PATH, device_id);
    let (status, resp) = http_tls_request(
        &api_host(),
        TlsRequest {
            method: "DELETE",
            path: &path,
            body: None,
            auth: Some(token),
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("leave mesh: HTTP {} — {}", status, resp))
    }
}

fn enroll_error(status: u16, body: &str) -> String {
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    match (status, code.as_str()) {
        (402, "plan_required") => "Your plan does not include the mesh network.".to_string(),
        (402, "device_limit") => "You have reached the device limit for your plan.".to_string(),
        (401, _) | (403, _) => "Sign in again to join the mesh network.".to_string(),
        _ => format!("Could not join the mesh network: HTTP {} — {}", status, body),
    }
}

pub fn identity_path() -> Option<std::path::PathBuf> {
    crate::dirs_next().map(|d| d.join(IDENTITY_FILE))
}

pub fn load_identity() -> Option<MeshIdentity> {
    let path = identity_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_identity(identity: &MeshIdentity) {
    let path = match identity_path() {
        Some(p) => p,
        None => return,
    };
    if let Ok(json) = serde_json::to_string_pretty(identity) {
        if std::fs::write(&path, json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

pub fn clear_identity() {
    if let Some(path) = identity_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn os_name() -> String {
    std::env::consts::OS.to_string()
}

pub fn os_version() -> String {
    let (program, args) = if cfg!(target_os = "macos") {
        ("sw_vers", vec!["-productVersion"])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "ver"])
    } else {
        ("uname", vec!["-r"])
    };
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
