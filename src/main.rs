use axum::{routing::{get, post}, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use tokio::net::TcpListener;
use axum::serve;
use std::str::FromStr;
use ed25519_dalek::{Verifier, PublicKey, Signature};

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

async fn root() -> &'static str {
    "✅ Solana Rust Server is running!"
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

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> Json<Result<SuccessResponse<VerifyMessageResponse>, ErrorResponse>> {
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Invalid base58 pubkey".into(),
            }));
        }
    };

    let pubkey = match PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "PublicKey wrong size".into(),
            }));
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Base64 decode failed".into(),
            }));
        }
    };

    let signature = match Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Signature wrong size".into(),
            }));
        }
    };

    let is_valid = pubkey.verify(payload.message.as_bytes(), &signature).is_ok();

    Json(Ok(SuccessResponse {
        success: true,
        data: VerifyMessageResponse {
            valid: is_valid,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    }))
}


#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn create_token(Json(payload): Json<CreateTokenRequest>) -> Json<SuccessResponse<Instruction>> {
    let mint = Pubkey::from_str(&payload.mint).unwrap();
    let mint_authority = Pubkey::from_str(&payload.mint_authority).unwrap();

    let ix = token_instruction::initialize_mint(
        &spl_token::ID,
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    ).unwrap();

    Json(SuccessResponse {
        success: true,
        data: ix,
    })
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(payload): Json<MintTokenRequest>) -> Json<SuccessResponse<Instruction>> {
    let ix = token_instruction::mint_to(
        &spl_token::ID,
        &Pubkey::from_str(&payload.mint).unwrap(),
        &Pubkey::from_str(&payload.destination).unwrap(),
        &Pubkey::from_str(&payload.authority).unwrap(),
        &[],
        payload.amount,
    ).unwrap();

    Json(SuccessResponse {
        success: true,
        data: ix,
    })
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

async fn send_sol(Json(payload): Json<SendSolRequest>) -> Json<SuccessResponse<Instruction>> {
    let ix = system_instruction::transfer(
        &Pubkey::from_str(&payload.from).unwrap(),
        &Pubkey::from_str(&payload.to).unwrap(),
        payload.lamports,
    );

    Json(SuccessResponse {
        success: true,
        data: ix,
    })
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn send_token(Json(payload): Json<SendTokenRequest>) -> Json<SuccessResponse<Instruction>> {
    let ix = token_instruction::transfer(
        &spl_token::ID,
        &Pubkey::from_str(&payload.mint).unwrap(),
        &Pubkey::from_str(&payload.destination).unwrap(),
        &Pubkey::from_str(&payload.owner).unwrap(),
        &[],
        payload.amount,
    ).unwrap();

    Json(SuccessResponse {
        success: true,
        data: ix,
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server running at http://0.0.0.0:3000");

    serve(listener, app).await.unwrap();
}
