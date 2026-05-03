//! HTTP route handlers.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use chrono::{Duration, Utc};
use gr_protocol::license::{LicensePayload, LicenseToken};
use serde::Serialize;
use std::sync::Arc;

use crate::directory::{BridgeDirectory, SignedDirectory};
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/v1/health", get(health))
        .route("/v1/info", get(info))
        .route("/v1/bridges", get(bridges))
        .route("/v1/signup", post(signup))
        .with_state(state)
}

async fn index() -> &'static str {
    "lowping backend — see https://github.com/twitchbionx/lowping for client / docs\n"
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct InfoResponse {
    service: &'static str,
    /// Backend's pubkey. Clients embed this at install time so they can
    /// verify the bridge directory and license tokens without trusting TLS alone.
    backend_pubkey_hex: String,
    /// What scopes this backend issues tokens for (forward compat hook).
    supported_scopes: Vec<&'static str>,
}

async fn info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    Json(InfoResponse {
        service: "lowping-backend",
        backend_pubkey_hex: hex::encode(state.verifying_key.as_bytes()),
        supported_scopes: vec!["any-bridge"],
    })
}

async fn bridges(State(state): State<Arc<AppState>>) -> Result<Json<SignedDirectory>, AppError> {
    let cfg = state.config.read();
    let now = Utc::now();
    let directory = BridgeDirectory {
        version: 1,
        issued_at: now,
        expires_at: now + Duration::seconds(cfg.directory_ttl_secs as i64),
        bridges: cfg.bridges.iter().filter(|b| b.enabled).cloned().collect(),
    };
    let signed = SignedDirectory::sign(&directory, &state.signing_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(signed))
}

#[derive(Serialize)]
struct SignupResponse {
    user_id: u32,
    license_token: String,
    expires_at_unix: i64,
}

/// MVP signup: no email, no password, no payment. Just hand out a token.
/// (Replace with real account flow before going public.)
async fn signup(State(state): State<Arc<AppState>>) -> Result<Json<SignupResponse>, AppError> {
    let cfg = state.config.read();
    let user_id = state.issue_user_id();
    let now = Utc::now().timestamp();
    let payload = LicensePayload {
        user_id,
        issued_at: now,
        expires_at: now + cfg.token_ttl_secs as i64,
        scope: 1, // bit 0 = "any bridge"
    };
    let token = LicenseToken::sign(payload, &state.signing_key);
    Ok(Json(SignupResponse {
        user_id,
        license_token: token.to_string_b64(),
        expires_at_unix: payload.expires_at,
    }))
}

// ---------- error type ----------

#[derive(Debug)]
pub enum AppError {
    Internal(String),
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
        };
        (status, msg).into_response()
    }
}
