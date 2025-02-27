use axum::{
    body::Body,
    extract::{Json, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};
use tracing::{debug, error, info};

pub struct AuthError {
    message: String,
    status_code: StatusCode,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response<Body> {
        let body = Json(json!({
            "error": self.message,
        }));

        (self.status_code, body).into_response()
    }
}

#[derive(Clone)]
pub struct CurrentUser {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,

    pub access_level: AccessLevel,
}

#[derive(Clone)]
pub struct MinAccessState(pub AccessLevel);

#[derive(Clone, Debug, PartialEq)]
pub enum AccessLevel {
    _Guest,
    User,
    Admin,
}

impl PartialOrd for AccessLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use AccessLevel::*;
        let order = |level: &AccessLevel| -> isize {
            match level {
                _Guest => 0,
                User => 1,
                Admin => 2,
            }
        };
        let order_self = order(self);
        let order_other = order(other);

        order_self.partial_cmp(&order_other)
    }

    fn lt(&self, other: &AccessLevel) -> bool {
        std::matches!(self.partial_cmp(other), Some(std::cmp::Ordering::Less))
    }

    fn le(&self, other: &AccessLevel) -> bool {
        std::matches!(
            self.partial_cmp(other),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        )
    }

    fn gt(&self, other: &AccessLevel) -> bool {
        std::matches!(self.partial_cmp(other), Some(std::cmp::Ordering::Greater))
    }

    fn ge(&self, other: &AccessLevel) -> bool {
        std::matches!(
            self.partial_cmp(other),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        )
    }
}

#[derive(Serialize, Deserialize)]
// Define a structure for holding claims data used in JWT tokens
pub struct Claims {
    pub exp: usize,    // Expiry time of the token
    pub iat: usize,    // Issued at time of the token
    pub email: String, // Email associated with the token
}

// Define a structure for holding sign-in data
#[derive(Deserialize)]
pub struct SignInData {
    pub email: String,    // Email entered during sign-in
    pub password: String, // Password entered during sign-in
}

#[axum::debug_handler]
// Function to handle sign-in requests
pub async fn sign_in(
    cookies: Cookies,
    Json(user_data): Json<SignInData>, // JSON payload containing sign-in data
) -> Result<Json<String>, StatusCode> {
    /* let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key); */

    // Attempt to retrieve user information based on the provided email
    let user = match retrieve_user_by_email(&user_data.email) {
        Some(user) => user, // User found, proceed with authentication
        None => return Err(StatusCode::UNAUTHORIZED), // User not found, return unauthorized status
    };

    // Verify the password provided against the stored hash
    if !verify_password(&user_data.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    // Handle bcrypt errors
    {
        return Err(StatusCode::UNAUTHORIZED); // Password verification failed, return unauthorized status
    }

    // Generate a JWT token for the authenticated user
    let token = encode_jwt(user.email.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // Handle JWT encoding errors

    debug!("Generated new login token for {}", user.email);
    let mut cookie = Cookie::new("jwt", token);

    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);

    cookies.add(cookie);

    info!("Successful login for {}", user_data.email);

    // Return the token as a JSON-wrapped string
    Ok(Json("ok".to_string()))
}

#[derive(Clone, Debug, Serialize)]
pub enum RegisterResult {
    Success,
    AlreadyExists,
    PasswordTooShort,
}

#[axum::debug_handler]
pub async fn register(
    Json(user_data): Json<SignInData>, // JSON payload containing sign-in data
) -> Result<Json<RegisterResult>, StatusCode> {
    // Attempt to retrieve user information based on the provided email
    if user_exists(&user_data.email) {
        return Ok(Json(RegisterResult::AlreadyExists));
    }

    let min_password_length = dotenv::var("MIN_PASSWORD_LENGTH")
        .unwrap_or("12".to_string())
        .parse::<usize>()
        .unwrap_or(12);
    if user_data.password.len() < min_password_length {
        return Ok(Json(RegisterResult::PasswordTooShort));
    }

    // Verify the password provided against the stored hash
    let password_hash = hash_password(&user_data.password);
    if password_hash.is_err() {
        error!(
            "Failed to hash password during registration: {}",
            password_hash.unwrap_err()
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    info!("Successful registration for {}", user_data.email);

    // Return the token as a JSON-wrapped string
    Ok(Json(RegisterResult::Success))
}

pub fn logout_session(cookies: Cookies) {
    let mut c = Cookie::new("jwt", "");
    c.make_removal();
    cookies.add(c);
}

pub fn get_jwt_claims(cookies: Cookies) -> Option<Claims> {
    match cookies.get("jwt") {
        Some(cookie) => {
            let jwt_val = cookie.value_trimmed();

            let claims = decode_jwt(jwt_val.to_string());

            if let Ok(claims) = claims {
                let exp = chrono::DateTime::from_timestamp(claims.claims.exp as i64, 0);
                let iat = chrono::DateTime::from_timestamp(claims.claims.iat as i64, 0);
                if iat.is_none() {
                    // Bad creation date contents
                    logout_session(cookies);
                    return None;
                }

                if let Some(exp) = exp {
                    if exp <= Utc::now() {
                        // Session expired
                        logout_session(cookies);
                        return None;
                    } else {
                        info!("Session still valid");
                    }
                } else {
                    // Bad expiration date contents
                    logout_session(cookies);
                    return None;
                }

                return Some(Claims {
                    exp: claims.claims.exp,
                    iat: claims.claims.iat,
                    email: claims.claims.email,
                });
            } else {
                info!("Bad cookie contents");
            }
        }
        None => {}
    }

    None
}

// Function to simulate retrieving user data from a database based on email
fn retrieve_user_by_email(email: &str) -> Option<CurrentUser> {
    // For demonstration purposes, a hardcoded user is returned based on the provided email
    if email != "my.email@mailer.com" {
        return None;
    }
    let current_user: CurrentUser = CurrentUser {
        email: "my.email@mailer.com".to_string(),
        first_name: "Eze".to_string(),
        last_name: "Sunday".to_string(),
        password_hash: "$2b$12$Gwf0uvxH3L7JLfo0CC/NCOoijK2vQ/wbgP.LeNup8vj6gg31IiFkm".to_string(),
        access_level: AccessLevel::User,
    };
    Some(current_user) // Return the hardcoded user
}

fn user_exists(email: &String) -> bool {
    email == &"my.email@mailer.com".to_string()
}

pub async fn authorization_middleware(
    State(min_access_level): State<MinAccessState>,
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, Redirect> {
    /* if req.headers().get(CONTENT_TYPE).unwrap() != "application/json" {
        return Err(StatusCode::BAD_REQUEST);
    } */
    let cookies = req.extensions().get::<Cookies>().cloned();
    if cookies.is_none() {
        error!("Internal server error, couldn't load cookies in authorization_middleware.");
        return Err(Redirect::to("/"));
    }
    let cookies = cookies.unwrap();
    let jwt_cookie = cookies.get("jwt");

    if jwt_cookie.is_none() {
        info!("Unauthorized user access, no 'jwt' cookie found.");
        return Err(Redirect::to("/"));
    }
    let jwt_cookie = jwt_cookie.unwrap();
    let jwt_token = jwt_cookie.value_trimmed().to_string();

    let token_data = match decode_jwt(jwt_token) {
        Ok(data) => data,
        Err(_e) => {
            info!("Unauthorized user access, unable to decode claims.");
            return Err(Redirect::to("/"));
        }
    };

    // Fetch the user details from the database
    let current_user = match retrieve_user_by_email(&token_data.claims.email) {
        Some(user) => user,
        None => {
            info!("Unauthorized user access, unable to find user from jwt claims.");
            return Err(Redirect::to("/"));
        }
    };

    // Only if allowed
    if current_user.access_level < min_access_level.0 {
        info!(
            "User {} with AccessLevel '{:?}' tried to visit page '{:?}' with AccessLevel '{:?}'",
            current_user.email,
            current_user.access_level,
            req.uri().path_and_query(),
            min_access_level.0
        );
        return Err(Redirect::to("/"));
    }

    req.extensions_mut().insert(current_user);
    Ok(next.run(req).await)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hash = hash(password, DEFAULT_COST)?;
    Ok(hash)
}

pub fn encode_jwt(email: String) -> Result<String, StatusCode> {
    let jwt_secret = dotenv::var("JWT_SECRET");
    match jwt_secret {
        Ok(jwt_secret) => {
            let expiration_timemout = dotenv::var("SESSION_COOKIE_INVALIDATION_TIMEOUT")
                .unwrap_or("43200".to_string())
                .parse::<usize>()
                .unwrap_or(43200);

            let now = Utc::now();
            let expire: chrono::TimeDelta = if expiration_timemout > 0 {
                Duration::seconds(expiration_timemout as i64)
            } else {
                Duration::seconds(i64::MAX / 1_000)
            };
            let exp = (now + expire).timestamp() as usize;

            let iat: usize = now.timestamp() as usize;
            let claim = Claims { iat, exp, email };

            encode(
                &Header::default(),
                &claim,
                &EncodingKey::from_secret(jwt_secret.as_ref()),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            error!("No JWT encryption secret in .env found: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub fn decode_jwt(jwt_token: String) -> Result<TokenData<Claims>, StatusCode> {
    let jwt_secret = dotenv::var("JWT_SECRET");
    match jwt_secret {
        Ok(jwt_secret) => {
            let result: Result<TokenData<Claims>, StatusCode> = decode(
                &jwt_token,
                &DecodingKey::from_secret(jwt_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            result
        }
        Err(e) => {
            error!("No JWT secret in .env found: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
