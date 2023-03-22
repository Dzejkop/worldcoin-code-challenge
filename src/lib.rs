//! Context:
//! - We use some API that requires authentication
//! - The authentication can be thought of as a blackbox call to `auth::authenticate`
//! - The authentication returns an access token that expires after a certain amount of time
//! - We want to design an internal library for handling this process
//! - Assume that constructing a `reqwest::Client` is expensive and we don't want to recreate it everytime we need a client
//! - The API of this library is not set in stone, feel free to change almost any aspect of this code

use std::collections::HashMap;
use std::fmt::Debug;

use once_cell::sync::Lazy;
use reqwest::header::HeaderValue;
use reqwest::Client;
use tokio::sync::Mutex;

// Public auth input data
const CLIENT_ID: &str = "1bpd19lcr33qvg5cr3oi79rdap";
const POOL_ID: &str = "us-west-2_iLmIggsiy";

#[derive(Debug)]
struct ExpiringClient {
    client: Client,
    expiration_time: i64,
}

static CLIENTS: Lazy<Mutex<HashMap<String, ExpiringClient>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub async fn refresh_client(api_key: String, api_secret: String) -> Result<Client, String> {
    let now = chrono::Utc::now().timestamp();

    let mut clients = CLIENTS.lock().await;
    if let Some(client) = clients.get(&api_key) {
        if now < client.expiration_time {
            return Ok(client.client.clone());
        }
    }

    let res = auth::authenticate(CLIENT_ID, POOL_ID, &api_key, &api_secret)
        .await
        .map_err(|err| format!("Authentication failed: {err}"))?;

    let access_token = res.access_token();

    let mut auth_value = HeaderValue::from_str(&format!("Bearer {access_token}"))
        .map_err(|err| format!("Invalid header value: {err}"))?;
    auth_value.set_sensitive(true);

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);
    headers.insert(
        "X-Api-Key",
        HeaderValue::from_str(&api_key).map_err(|err| format!("Invalid header value: {err}"))?,
    );

    let client = Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|err| format!("Failed to build client: {err}"))?;

    clients.insert(
        api_key.to_string(),
        ExpiringClient {
            client: client.clone(),
            expiration_time: now + res.expires_in(),
        },
    );

    Ok(client)
}

/// A placeholder auth implementation
mod auth {
    pub struct AuthOutput {
        access_token: String,
        expires_in: i64,
    }

    impl AuthOutput {
        pub fn access_token(&self) -> &str {
            &self.access_token
        }

        pub fn expires_in(&self) -> i64 {
            self.expires_in
        }
    }

    pub async fn authenticate(
        client_id: &str,
        pool_id: &str,
        api_key: &str,
        password: &str,
    ) -> anyhow::Result<AuthOutput> {
        Ok(AuthOutput {
            access_token: format!("{client_id}:{pool_id}:{api_key}:{password}"),
            expires_in: 3600,
        })
    }
}
