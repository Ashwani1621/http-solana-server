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
use axum::http::StatusCode;

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

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>
    ) -> Json<Result<SuccessResponse<VerifyMessageResponse>, ErrorResponse>> {
    // Decode public key from base58
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Invalid base58 pubkey or incorrect size".into(),
            }));
        }
    };

    // Decode signature from base64
    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return Json(Err(ErrorResponse {
                success: false,
                error: "Invalid base64 signature or incorrect size".into(),
            }));
        }
    };

    // Convert to PublicKey and Signature
    let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();
    let signature = Signature::from_bytes(&signature_bytes).unwrap();

    // Verify
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



#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    mint: String,

    #[serde(rename = "mintAuthority")]
    mint_authority: String,

    decimals: u8,
}


#[derive(Debug, Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}



#[derive(Debug, Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<SuccessResponse<InstructionData>>, (StatusCode, Json<ErrorResponse>)> {
    // Parse mint pubkey
    let mint_pubkey = Pubkey::from_str(&payload.mint).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Invalid mint public key".to_string(),
            }),
        )
    })?;

    // Parse mint authority pubkey
    let mint_authority_pubkey = Pubkey::from_str(&payload.mint_authority).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Invalid mintAuthority public key".to_string(),
            }),
        )
    })?;

    // Generate the instruction
    let ix: Instruction = token_instruction::initialize_mint(
        &spl_token::ID,
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: format!("Failed to create instruction: {}", e),
            }),
        )
    })?;

    // Encode instruction data as base64
    let instruction_data_base64 = general_purpose::STANDARD.encode(&ix.data);

    // Convert account metas
    let accounts: Vec<AccountMetaResponse> = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    // Create final structured response
    let response = InstructionData {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: instruction_data_base64,
    };

    Ok(Json(SuccessResponse {
        success: true,
        data: response,
    }))
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}


#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<Json<SuccessResponse<InstructionResponse>>, (StatusCode, Json<ErrorResponse>)> {
    // Parse pubkeys
    let mint = Pubkey::from_str(&payload.mint).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Invalid mint public key".to_string(),
            }),
        )
    })?;

    let destination = Pubkey::from_str(&payload.destination).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Invalid destination public key".to_string(),
            }),
        )
    })?;

    let authority = Pubkey::from_str(&payload.authority).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Invalid authority public key".to_string(),
            }),
        )
    })?;

    // Build the instruction
    let ix: Instruction = token_instruction::mint_to(
        &spl_token::ID,
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: format!("Failed to create instruction: {}", e),
            }),
        )
    })?;

    // Convert accounts
    let accounts: Vec<AccountMetaResponse> = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    // Encode instruction data
    let instruction_data = general_purpose::STANDARD.encode(&ix.data);

    // Final structured response
    let response = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Ok(Json(SuccessResponse {
        success: true,
        data: response,
    }))
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
