use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use tokio::net::TcpListener;
use axum::serve;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> Json<SuccessResponse<KeypairData>> {
    let keypair = Keypair::new();
    Json(SuccessResponse {
        success: true,
        data: KeypairData {
            pubkey: keypair.pubkey().to_string(),
            secret: bs58::encode(keypair.to_bytes()).into_string(),
        },
    })
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignedMessage {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(Json(payload): Json<SignMessageRequest>) -> Json<Result<SuccessResponse<SignedMessage>, ErrorResponse>> {
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Invalid secret key".into(),
            }))
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Invalid keypair format".into(),
            }))
        }
    };

    let signature = keypair.sign_message(payload.message.as_bytes());

    Json(Ok(SuccessResponse {
        success: true,
        data: SignedMessage {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: payload.message,
        },
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/message/sign", post(sign_message));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server running at http://0.0.0.0:3000");

    serve(listener, app).await.unwrap();
}
