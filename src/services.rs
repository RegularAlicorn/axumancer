use std::net::SocketAddr;

use axum::{
    extract::Path,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    response::{Html, Redirect},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{auth::CurrentUser, helper::file_exists_safe, ServerState};

#[derive(Serialize, Deserialize)]
struct UserResponse {
    email: String,
    first_name: String,
    last_name: String,
}

pub fn get_content_data(
    page: String,
    server_state: ServerState,
    socket_addr: SocketAddr,
) -> (StatusCode, String) {
    let file_path = format!("content/{}", page);
    info!("{} is loading page: {}", socket_addr.ip(), file_path);

    if file_exists_safe(&server_state.base_directory, &file_path) {
        if let Ok(html_data) = std::fs::read_to_string(file_path) {
            (StatusCode::OK, html_data)
        } else {
            if let Ok(html_data) = std::fs::read_to_string("status_pages/404.html") {
                (StatusCode::NOT_FOUND, html_data)
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "<h1>Internal Server Error</h1>".to_string(),
                )
            }
        }
    } else {
        if let Ok(html_data) = std::fs::read_to_string("status_pages/404.html") {
            (StatusCode::NOT_FOUND, html_data)
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "<h1>Internal Server Error</h1>".to_string(),
            )
        }
    }
}

pub mod routes {
    use tower_cookies::Cookies;

    use crate::{
        auth::{get_jwt_claims, logout_session},
        StatusPage,
    };

    use super::*;

    pub async fn index(
        cookies: Cookies,
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> (StatusCode, impl IntoResponse) {
        let mut content_data = get_content_data("index.html".to_string(), server_state, addr);
        content_data.1 = content_data.1.replace("{{addr}}", &addr.to_string());

        let mut has_session_str = "".to_string();
        let jwt_claims_opt = get_jwt_claims(cookies);
        if let Some(claims) = jwt_claims_opt {
            has_session_str = format!(
                "<a href='/home'>Member area for {}</a><br><br>",
                claims.email
            );
        }

        content_data.1 = content_data.1.replace("{{has_session}}", &has_session_str);

        (content_data.0, Html(content_data.1))
    }

    pub async fn register(
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> (StatusCode, impl IntoResponse) {
        let content_data = get_content_data("register.html".to_string(), server_state, addr);

        (content_data.0, Html(content_data.1))
    }

    pub async fn admin_index(
        cookies: Cookies,
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> (StatusCode, impl IntoResponse) {
        let mut content_data = get_content_data("admin_index.html".to_string(), server_state, addr);
        content_data.1 = content_data.1.replace("{{addr}}", &addr.to_string());

        let mut has_session_str = "".to_string();
        let jwt_claims_opt = get_jwt_claims(cookies);
        if let Some(claims) = jwt_claims_opt {
            has_session_str = format!(
                "<a href='/home'>Member area for {}</a><br><br>",
                claims.email
            );
        }

        content_data.1 = content_data.1.replace("{{has_session}}", &has_session_str);

        (content_data.0, Html(content_data.1))
    }

    pub async fn user_handler(Path(user_id): Path<u32>) -> String {
        format!("User ID: {}", user_id)
    }

    pub async fn missing_page_404(
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> (StatusCode, impl IntoResponse) {
        let status = server_state.get_status_page(StatusPage::Status404);
        info!("{} 404'd", addr.ip());
        (status.0, Html(status.1))
    }

    pub async fn anything_else() -> Redirect {
        Redirect::to("/404")
    }

    pub async fn show_user(Extension(current_user): Extension<CurrentUser>) -> impl IntoResponse {
        Json(UserResponse {
            email: current_user.email,
            first_name: current_user.first_name,
            last_name: current_user.last_name,
        })
    }

    pub async fn get_protected(
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> impl IntoResponse {
        Html(get_content_data(
            "protected.html".to_string(),
            server_state,
            addr,
        ))
    }

    pub async fn logout(
        cookies: Cookies,
        State(server_state): State<ServerState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> impl IntoResponse {
        logout_session(cookies);

        Html(get_content_data(
            "logout.html".to_string(),
            server_state,
            addr,
        ))
    }
}
