use anyhow::anyhow;
use auth::{AccessLevel, MinAccessState};
use axum::{
    http::StatusCode,
    middleware::{self},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rand::{rngs::OsRng, TryRngCore};
use rusqlite::{Connection, DatabaseName};
use services::routes::*;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::OnceLock};
use tower_cookies::{CookieManagerLayer, Cookies, Key};
use tower_http::{
    compression::CompressionLayer,
    services::ServeFile,
    trace::{self, TraceLayer},
};
use tracing::{error, info, Level}; // Cryptographically secure RNG

mod auth;
mod helper;
mod services;

static KEY: OnceLock<Key> = OnceLock::new();

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum StatusPage {
    Status404,
}

#[derive(Clone, Debug)]
pub struct ServerState {
    pub base_directory: PathBuf,
    pub dev_mode: bool,
    pub status_pages: HashMap<StatusPage, String>,
    pub db_path: PathBuf,
}

impl ServerState {
    pub fn new(
        dev_mode: bool,
        base_directory: PathBuf,
        status_pages_vec: Vec<(StatusPage, String)>,
        db_path: PathBuf,
    ) -> Self {
        let mut status_pages = HashMap::new();
        for (e, p) in status_pages_vec {
            status_pages.insert(e, p);
        }

        Self {
            base_directory,
            dev_mode,
            status_pages,
            db_path,
        }
    }
    pub fn authentication_db(&self) -> String {
        self.db_path
            .join("db_authentication.sqlite")
            .to_string_lossy()
            .to_string()
    }
    pub fn get_status_page(&self, status: StatusPage) -> (StatusCode, String) {
        if let Some(file) = self.status_pages.get(&status) {
            if let Ok(html_data) = std::fs::read_to_string(&format!("status_pages/{}", file)) {
                return (StatusCode::NOT_FOUND, html_data);
            } else {
                error!("Missing status page {:?}", status);
            }
        }
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "<h1>Internal Server Error</h1>".to_string(),
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("dotenv failed to load");

    let trace_max_level = dotenv::var("TRACE_MAX_LEVEL")
        .map_err(|e| {
            error!("Failed to load Trace Max Level: {}\n\nUsing 'Info'", e);
            "INFO".to_string()
        })
        .unwrap();
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "tower_http=warn,{}={}",
                    env!("CARGO_CRATE_NAME"),
                    trace_max_level
                )
                .into()
            }),
        )
        .pretty()
        .compact()
        .init();
    println!("Tracing for package set to level: {}", trace_max_level);

    // Starting server
    info!("⚡Raising from slumber⚡");

    // Are we in dev mode?
    let mut dev_mode = false;
    if let Ok(env_var) = dotenv::var("DEV_MODE") {
        dev_mode = env_var.parse::<bool>().unwrap_or(false);
    }
    if !dev_mode {
        info!("PRODUCTION!");
    } else {
        info!("DEVELOPMENT MODE");
    }

    info!("Checking your magic pouch..");

    // Loading the base directory
    // If the cargo manifest directory environment variable exists, we can use this
    // Otherwise this is running
    let mut base_directory = Err(());
    if let Ok(base) = dotenv::var("BASE_DIRECTORY") {
        let buf = PathBuf::from(base);
        if !buf.try_exists().unwrap_or(false) {
            error!("Bad path given in .env. Check if it exists and Axumancer has permissions to access it: {:?}", buf);
        } else {
            info!("Base directory is given from .env");
        }
        base_directory = Ok(buf);
    }

    if base_directory.is_err() {
        if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
            info!("Base directory is taken from CARGO_MANIFEST_DIR");
            let buf = PathBuf::from(dir);
            if !buf.try_exists().unwrap_or(false) {
                error!("Bad path given in .env. Check if it exists and Axumancer has permissions to access it: {:?}", buf);
            } else {
                info!("Base directory is given from .env");
            }
            base_directory = Ok(buf);
        }
    }

    // Verify, whether we found the base directory already through .env or environment variable
    let exists = if let Ok(e) = base_directory.as_ref().unwrap().try_exists() {
        e
    } else {
        false
    };
    if !exists && !dev_mode {
        info!("Base directory is taken from current executable directory. This fails in dev_mode!");
        base_directory = Ok(PathBuf::from(
            std::env::current_dir().expect("Failed to get current directory"),
        )
        .join(file!())
        .parent()
        .expect("Failed to get parent directory of main.rs")
        .to_path_buf());
    } else if !exists && dev_mode {
        error!("Unable to find the base directory. Set the 'BASE_DIRECTORY=' key in your .env");
        return Err(anyhow!("returning to slumber.."));
    }

    if let Ok(ref dir) = base_directory {
        info!("Axumancer found its magic pouch in {:?}", dir);
    } else {
        error!("Axumancer wasn't able to find where it put its magic pouch, aborting! (Failed to request base directory)");
        return Err(anyhow!("returning to slumber.."));
    }
    // At this point we can drop the result, since we returned from the function otherwise
    let base_directory = base_directory.unwrap();

    // Check whether the database path exists
    let mut db_base_path = base_directory.clone();
    db_base_path.push("db");
    let exists = if let Ok(e) = db_base_path.try_exists() {
        e
    } else {
        false
    };
    if !exists {
        error!("Unable to find [basepath]/db/ for database files.");
        return Err(anyhow!("returning to slumber.."));
    }
    info!("Database folder available.");

    let mut auth_db = PathBuf::from(db_base_path.clone());
    auth_db.push("db_authentication.sqlite");
    let exists = if let Ok(e) = auth_db.try_exists() {
        e
    } else {
        false
    };
    if !exists {
        error!("Unable to find the authentication datbase. Try installing the database (/scripts/create_database.sh)");
        return Err(anyhow!("returning to slumber.."));
    }
    info!("Authentication database available.");

    // Checking for special status pages
    let status_404 = if let Ok(name) = dotenv::var("STATUS_404") {
        name
    } else {
        "404.html".to_string()
    };

    let all_status_pages = vec![(StatusPage::Status404, status_404)];
    let mut missing_pages = vec![];
    let mut check_status_pages = true;
    for (_e, p) in all_status_pages.iter() {
        if let Ok(exists) = std::fs::exists(format!("status_pages/{}", p)) {
            check_status_pages = check_status_pages && exists;
            if !exists {
                missing_pages.push(p);
            }
        }
    }
    if check_status_pages {
        info!("Server status pages OK.");
    } else {
        error!("Missing status pages");
        for missing in missing_pages {
            println!("Missing {}", missing);
        }
    }

    // Create the common server state
    let server_state = ServerState::new(dev_mode, base_directory, all_status_pages, db_base_path);

    let conn = Connection::open(server_state.authentication_db());
    if conn.is_err() {
        error!("Unable to connect to the database. {}", conn.unwrap_err());
        return Err(anyhow!("returning to slumber.."));
    }
    let conn = conn.unwrap();

    if let Ok(readonly) = conn.is_readonly(DatabaseName::Main) {
        if readonly {
            error!("Bad permissions on database, verify the server has write permissions on the directory and all files in /db");
            return Err(anyhow!("returning to slumber.."));
        }
    }
    info!("Database seems writeable");

    // Generate a new random crypt key if the .env variable is set to true
    let generate_crypt_key = dotenv::var("GENERATE_CRYPT_KEY")
        .unwrap_or("false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Only generate the key of in dev mode and the specific .env key is set to true
    // This key is not automatically used!
    // This is a DEV FEATURE. DO NOT USE IN PRODUCTION
    // Generate your production key cryptographically secure outside of this executable
    if server_state.dev_mode && generate_crypt_key {
        let mut rng = OsRng; // Initialize secure random number generator
        let mut random_bytes = [0u8; 64]; // Create a vector of 64 zeroed bytes
                                          // Fill the vector with random bytes
        match rng.try_fill_bytes(&mut random_bytes) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to create random Key: {}", e);
                return Err(anyhow!("returning to slumber.."));
            }
        }
        info!("New random crypt key: {:?}", hex::encode(&random_bytes));
    }

    // Key to encrypt/decrypt cookies of this axumancer
    let key_hex;
    if let Ok(cookie_key) = dotenv::var("COOKIE_KEY") {
        key_hex = cookie_key;
    } else {
        error!("COOKIE_KEY not found in .env");
        return Err(anyhow!("returning to slumber.."));
    }

    let key_bytes = hex::decode(key_hex).expect("Failed to decode COOKIE_KEY from hex");
    if key_bytes.len() != 64 {
        error!("COOKIE_KEY must be exactly 64 bytes");
    }

    // If there is no cookie key, we can't use private cookies. It's an issue we shouldn't work around without admin interfering -> server crashes right away.
    KEY.set(Key::from(&key_bytes))
        .expect("COOKIE_KEY not found in .env");

    let app = Router::new()
        .route_service("/favicon.ico", ServeFile::new("assets/favicon/favicon.ico"))
        .route_service("/core.js", ServeFile::new("assets/core.js"))
        .route_service("/style.css", ServeFile::new("assets/style.css"))
        .route("/", get(index))
        .route("/secret", get(get_cookies))
        .route("/user", get(user_handler))
        .route("/404", get(missing_page_404))
        .route("/signin", get(signin).post(auth::sign_in))
        .route("/register", get(register).post(auth::register))
        .route("/logout", get(logout))
        .route(
            "/home",
            get(services::routes::get_protected).layer(middleware::from_fn_with_state(
                MinAccessState(AccessLevel::User),
                auth::authorization_middleware,
            )),
        )
        .route(
            "/protected/profile",
            get(services::routes::show_user).layer(middleware::from_fn_with_state(
                MinAccessState(AccessLevel::User),
                auth::authorization_middleware,
            )),
        )
        .route(
            "/admin",
            get(services::routes::admin_index).layer(middleware::from_fn_with_state(
                MinAccessState(AccessLevel::Admin),
                auth::authorization_middleware,
            )),
        )
        .layer(CookieManagerLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO))
                .on_request(trace::DefaultOnRequest::new().level(Level::INFO)),
        )
        .layer(CompressionLayer::new().br(true).gzip(true))
        .with_state(server_state)
        .fallback(anything_else);

    // write address like this to not make typos
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    //let listener = TcpListener::bind(addr).await?;

    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("key.pem"),
    )
    .await
    .expect("Failed to load certificate files: certs/cert.pem and certs/key.pem");

    // Only serve https, if the .env key is set
    let serve_https = dotenv::var("SERVE_HTTPS")
        .unwrap_or("false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    if serve_https {
        info!("Serving HTTPS-Minions!");
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        info!("Serving HTTP-Minions!");
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    }

    info!("returning to slumber..");
    Ok(())
}

// Still in testing at this moment
async fn get_cookies(cookies: Cookies) -> impl IntoResponse {
    //let key = KEY.get().unwrap();
    //let private_cookies = cookies.private(key);

    let cookie = cookies.get("jwt");
    Html(format!("{:#?}", cookie))
}
