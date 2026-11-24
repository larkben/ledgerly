use actix_files::Files;
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder,
    cookie::{Cookie, SameSite},
    get, post, web,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use chrono::{Datelike, Duration, NaiveDate, Timelike, Utc, Weekday};
use futures_util::TryStreamExt;
use mongodb::{
    Client, Collection, IndexModel,
    bson::{Document, doc, oid::ObjectId},
    options::IndexOptions,
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use std::{collections::HashMap, io, sync::Mutex};

struct AppState {
    users: Collection<Document>,
    finance: Collection<Document>,
    logins: Collection<Document>,
    sessions: Mutex<HashMap<String, (String, Vec<u8>)>>,
    market_history: Collection<Document>,
    market_symbols: Collection<Document>,
}
#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}
#[derive(Deserialize)]
struct FinanceBody {
    data: serde_json::Value,
}
#[derive(Deserialize)]
struct RecoverPassword {
    email: String,
    recovery_code: String,
    new_password: String,
}

fn is_admin_email(email: &str) -> bool {
    std::env::var("ADMIN_EMAILS")
        .unwrap_or_default()
        .split(',')
        .any(|allowed| allowed.trim().eq_ignore_ascii_case(email))
}
async fn record_login(logins: &Collection<Document>, user_id: &str) -> mongodb::error::Result<()> {
    logins
        .insert_one(doc! { "user_id": user_id, "logged_at": Utc::now().to_rfc3339() })
        .await?;
    Ok(())
}
fn seal(key: &[u8], plain: &[u8]) -> Result<String, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| ())?;
    Ok(format!("{}.{}", B64.encode(nonce), B64.encode(encrypted)))
}
fn open(key: &[u8], value: &str) -> Result<Vec<u8>, ()> {
    let (n, c) = value.split_once('.').ok_or(())?;
    let nonce = B64.decode(n).map_err(|_| ())?;
    let encrypted = B64.decode(c).map_err(|_| ())?;
    if nonce.len() != 12 {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted.as_ref())
        .map_err(|_| ())
}
fn create_recovery_envelope(data_key: &[u8]) -> Result<(String, String, String), ()> {
    let mut code_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut code_bytes);
    let code = URL_SAFE_NO_PAD.encode(code_bytes);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut wrapping_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(code.as_bytes(), &salt, &mut wrapping_key)
        .map_err(|_| ())?;
    let wrapped = seal(&wrapping_key, data_key)?;
    Ok((code, B64.encode(salt), wrapped))
}
fn session(req: &HttpRequest, state: &AppState) -> Option<(String, String, Vec<u8>)> {
    let token = req.cookie("ledger_session")?.value().to_string();
    let (user_id, key) = state.sessions.lock().ok()?.get(&token)?.clone();
    Some((token, user_id, key))
}
fn session_cookie(token: String) -> Cookie<'static> {
    let secure = std::env::var("COOKIE_SECURE")
        .map(|v| v != "false")
        .unwrap_or(false);
    Cookie::build("ledger_session", token)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(secure)
        .finish()
}
#[post("/api/register")]
async fn register(state: web::Data<AppState>, body: web::Json<Credentials>) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    if !email.contains('@') || body.password.len() < 12 {
        return HttpResponse::BadRequest()
            .body("Use a valid email and a password of at least 12 characters.");
    }
    let mut raw_salt = [0u8; 16];
    OsRng.fill_bytes(&mut raw_salt);
    let salt = SaltString::encode_b64(&raw_salt).unwrap();
    let argon = Argon2::default();
    let hash = match argon.hash_password(body.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut wrapping_key = [0u8; 32];
    if argon
        .hash_password_into(body.password.as_bytes(), &raw_salt, &mut wrapping_key)
        .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);
    let wrapped = match seal(&wrapping_key, &data_key) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let (recovery_code, recovery_salt, recovery_wrapped_key) =
        match create_recovery_envelope(&data_key) {
            Ok(v) => v,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
    let inserted = state.users.insert_one(doc! { "email": &email, "password_hash": hash, "key_salt": B64.encode(raw_salt), "wrapped_key": wrapped, "recovery_salt": recovery_salt, "recovery_wrapped_key": recovery_wrapped_key }).await;
    let user_id = match inserted {
        Ok(result) => match result.inserted_id.as_object_id() {
            Some(id) => id.to_hex(),
            None => return HttpResponse::InternalServerError().finish(),
        },
        Err(error) if error.to_string().contains("E11000") => {
            return HttpResponse::Conflict().body("That email is already registered.");
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if record_login(&state.logins, &user_id).await.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    create_session(&state, user_id, &data_key, Some(recovery_code))
}
#[post("/api/login")]
async fn login(state: web::Data<AppState>, body: web::Json<Credentials>) -> impl Responder {
    let row = match state
        .users
        .find_one(doc! { "email": body.email.trim().to_lowercase() })
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password."),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let Some(user_id) = row.get_object_id("_id").ok().map(|id| id.to_hex()) else {
        return HttpResponse::InternalServerError().finish();
    };
    let (Some(hash), Some(salt_b64), Some(wrapped)) = (
        row.get_str("password_hash").ok(),
        row.get_str("key_salt").ok(),
        row.get_str("wrapped_key").ok(),
    ) else {
        return HttpResponse::InternalServerError().finish();
    };
    let parsed = match PasswordHash::new(hash) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Invalid email or password.");
    }
    let salt = match B64.decode(salt_b64) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut wrapping_key = [0u8; 32];
    if Argon2::default()
        .hash_password_into(body.password.as_bytes(), &salt, &mut wrapping_key)
        .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    let data_key = match open(&wrapping_key, wrapped) {
        Ok(v) => v,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };
    if record_login(&state.logins, &user_id).await.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    create_session(&state, user_id, &data_key, None)
}
fn create_session(
    state: &AppState,
    user_id: String,
    key: &[u8],
    recovery_code: Option<String>,
) -> HttpResponse {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = B64.encode(bytes);
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.insert(token.clone(), (user_id, key.to_vec()));
    }
    let mut response = serde_json::json!({"ok":true});
    if let Some(code) = recovery_code {
        response["recovery_code"] = serde_json::Value::String(code);
    }
    HttpResponse::Ok()
        .cookie(session_cookie(token))
        .json(response)
}
#[get("/api/me")]
async fn me(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some((_token, user_id, _key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    match state.users.find_one(doc! { "_id": ObjectId::parse_str(user_id).unwrap_or_default() }).await {
        Ok(Some(user)) => match user.get_str("email") { Ok(email) => HttpResponse::Ok().json(serde_json::json!({"email":email,"is_admin":is_admin_email(email),"has_recovery":user.get_str("recovery_wrapped_key").is_ok()})), Err(_) => HttpResponse::InternalServerError().finish() },
        Ok(None) => HttpResponse::Unauthorized().finish(), Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
#[post("/api/recovery/rotate")]
async fn rotate_recovery(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some((_token, user_id, data_key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let (code, salt, wrapped) = match create_recovery_envelope(&data_key) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let result = state
        .users
        .update_one(
            doc! { "_id": ObjectId::parse_str(&user_id).unwrap_or_default() },
            doc! { "$set": { "recovery_salt": salt, "recovery_wrapped_key": wrapped } },
        )
        .await;
    match result {
        Ok(result) if result.matched_count == 1 => {
            HttpResponse::Ok().json(serde_json::json!({"recovery_code":code}))
        }
        Ok(_) => HttpResponse::Unauthorized().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
#[post("/api/recover-password")]
async fn recover_password(
    state: web::Data<AppState>,
    body: web::Json<RecoverPassword>,
) -> impl Responder {
    if body.new_password.len() < 12 {
        return HttpResponse::BadRequest().body("Use a password of at least 12 characters.");
    }
    let user = match state
        .users
        .find_one(doc! { "email": body.email.trim().to_lowercase() })
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().body("Email or recovery code is invalid."),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let Some(user_id) = user.get_object_id("_id").ok().map(|id| id.to_hex()) else {
        return HttpResponse::InternalServerError().finish();
    };
    let (Some(salt_b64), Some(wrapped_data_key)) = (
        user.get_str("recovery_salt").ok(),
        user.get_str("recovery_wrapped_key").ok(),
    ) else {
        return HttpResponse::Unauthorized().body("Email or recovery code is invalid.");
    };
    let salt = match B64.decode(salt_b64) {
        Ok(salt) => salt,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut recovery_key = [0u8; 32];
    if Argon2::default()
        .hash_password_into(
            body.recovery_code.trim().as_bytes(),
            &salt,
            &mut recovery_key,
        )
        .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    let data_key = match open(&recovery_key, wrapped_data_key) {
        Ok(key) => key,
        Err(_) => return HttpResponse::Unauthorized().body("Email or recovery code is invalid."),
    };

    let mut password_salt = [0u8; 16];
    OsRng.fill_bytes(&mut password_salt);
    let password_salt_string = SaltString::encode_b64(&password_salt).unwrap();
    let password_hash = match Argon2::default()
        .hash_password(body.new_password.as_bytes(), &password_salt_string)
    {
        Ok(hash) => hash.to_string(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut password_key = [0u8; 32];
    if Argon2::default()
        .hash_password_into(
            body.new_password.as_bytes(),
            &password_salt,
            &mut password_key,
        )
        .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    let wrapped_key = match seal(&password_key, &data_key) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let (new_recovery_code, new_recovery_salt, new_recovery_wrapped_key) =
        match create_recovery_envelope(&data_key) {
            Ok(v) => v,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
    let updated = state.users.update_one(doc! { "_id": ObjectId::parse_str(&user_id).unwrap_or_default() }, doc! { "$set": { "password_hash": password_hash, "key_salt": B64.encode(password_salt), "wrapped_key": wrapped_key, "recovery_salt": new_recovery_salt, "recovery_wrapped_key": new_recovery_wrapped_key } }).await;
    if !matches!(updated, Ok(ref result) if result.matched_count == 1) {
        return HttpResponse::InternalServerError().finish();
    }
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.retain(|_, (id, _)| id != &user_id);
    }
    HttpResponse::Ok().json(serde_json::json!({"ok":true,"recovery_code":new_recovery_code}))
}
#[get("/api/admin/users")]
async fn admin_users(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some((_token, user_id, _key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let admin = state
        .users
        .find_one(doc! { "_id": ObjectId::parse_str(user_id).unwrap_or_default() })
        .await;
    let Ok(Some(admin)) = admin else {
        return HttpResponse::Unauthorized().finish();
    };
    if !admin.get_str("email").ok().is_some_and(is_admin_email) {
        return HttpResponse::Forbidden().finish();
    }
    let users = match state.users.find(doc! {}).await {
        Ok(cursor) => cursor,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user_docs: Vec<Document> = match users.try_collect().await {
        Ok(rows) => rows,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let events = match state.logins.find(doc! {}).await {
        Ok(cursor) => cursor,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let login_docs: Vec<Document> = match events.try_collect().await {
        Ok(rows) => rows,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let cutoff = (Utc::now() - Duration::days(30)).to_rfc3339();
    let mut stats: HashMap<String, (Option<String>, i64)> = HashMap::new();
    for event in login_docs {
        let (Ok(uid), Ok(when)) = (event.get_str("user_id"), event.get_str("logged_at")) else {
            continue;
        };
        let entry = stats.entry(uid.to_owned()).or_insert((None, 0));
        if entry.0.as_deref().is_none_or(|last| when > last) {
            entry.0 = Some(when.to_owned());
        }
        if when >= cutoff.as_str() {
            entry.1 += 1;
        }
    }
    let response: Vec<serde_json::Value> = user_docs.into_iter().filter_map(|user| {
        let id = user.get_object_id("_id").ok()?.to_hex(); let email = user.get_str("email").ok()?.to_owned();
        let (last_login, logins_30d) = stats.remove(&id).unwrap_or((None, 0));
        Some(serde_json::json!({"id":id,"email":email,"last_login":last_login,"logins_30d":logins_30d}))
    }).collect();
    HttpResponse::Ok().json(response)
}
#[actix_web::delete("/api/admin/users/{target_id}")]
async fn delete_user(
    state: web::Data<AppState>,
    req: HttpRequest,
    target_id: web::Path<String>,
) -> impl Responder {
    let Some((_token, user_id, _key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let admin = state
        .users
        .find_one(doc! { "_id": ObjectId::parse_str(user_id).unwrap_or_default() })
        .await;
    let Ok(Some(admin)) = admin else {
        return HttpResponse::Unauthorized().finish();
    };
    if !admin.get_str("email").ok().is_some_and(is_admin_email) {
        return HttpResponse::Forbidden().finish();
    }
    let target = match ObjectId::parse_str(target_id.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    let target_id = target.to_hex();
    if state
        .finance
        .delete_many(doc! { "user_id": &target_id })
        .await
        .is_err()
        || state
            .logins
            .delete_many(doc! { "user_id": &target_id })
            .await
            .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    let user = match state.users.delete_one(doc! { "_id": target }).await {
        Ok(result) if result.deleted_count == 1 => true,
        Ok(_) => false,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if !user {
        return HttpResponse::NotFound().finish();
    }
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.retain(|_, (id, _)| id != &target_id);
    }
    HttpResponse::Ok().json(serde_json::json!({"ok":true}))
}
#[post("/api/logout")]
async fn logout(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Some(cookie) = req.cookie("ledger_session") {
        if let Ok(mut s) = state.sessions.lock() {
            s.remove(cookie.value());
        }
    }
    HttpResponse::Ok()
        .cookie(
            Cookie::build("ledger_session", "")
                .path("/")
                .http_only(true)
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .json(serde_json::json!({"ok":true}))
}
#[get("/api/finance")]
async fn get_finance(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some((_token, user_id, key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let found = state.finance.find_one(doc! { "user_id": user_id }).await;
    match found {
        Ok(Some(row)) => match row.get_str("payload").ok().and_then(|v| open(&key, v).ok()) { Some(bytes) => {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                sync_market_symbols(&state.market_symbols, &value).await;
            }
            HttpResponse::Ok().content_type("application/json").body(bytes)
        }, None => HttpResponse::InternalServerError().finish() },
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({"accounts":[],"cards":[],"purchases":[],"subscriptions":[],"goals":[],"debts":[],"investments":[],"retirement":[],"retirementSettings":{"annualRate":10,"years":30}})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
#[post("/api/finance")]
async fn save_finance(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<FinanceBody>,
) -> impl Responder {
    let Some((_token, user_id, key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let bytes = match serde_json::to_vec(&body.data) {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    let blob = match seal(&key, &bytes) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if state
        .finance
        .update_one(
            doc! { "user_id": &user_id },
            doc! { "$set": { "payload": blob } },
        )
        .upsert(true)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    sync_market_symbols(&state.market_symbols, &body.data).await;
    HttpResponse::Ok().json(serde_json::json!({"ok":true}))
}
fn market_symbols_from_finance(finance: &serde_json::Value) -> Vec<String> {
    let mut symbols = std::collections::HashSet::new();
    for item in finance
        .get("investments")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let category = item
            .get("category")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        if category.contains("crypto")
            || !(category.contains("stock")
                || category.contains("etf")
                || category.contains("fund"))
        {
            continue;
        }
        let Some(symbol) = item.get("ticker").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let symbol = symbol.trim().to_ascii_uppercase();
        if symbol.len() <= 32
            && !symbol.is_empty()
            && symbol
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':'))
        {
            symbols.insert(symbol);
        }
    }
    let mut symbols: Vec<_> = symbols.into_iter().collect();
    symbols.sort();
    symbols
}
async fn sync_market_symbols(index: &Collection<Document>, finance: &serde_json::Value) {
    for ticker in market_symbols_from_finance(finance) {
        let _ = index
            .update_one(
                doc! {"ticker": &ticker},
                doc! {"$setOnInsert": {"ticker": &ticker}},
            )
            .upsert(true)
            .await;
    }
}
#[get("/api/market-history")]
async fn get_market_history(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some((_token, user_id, key)) = session(&req, &state) else {
        return HttpResponse::Unauthorized().finish();
    };
    let finance = match state.finance.find_one(doc! {"user_id":&user_id}).await {
        Ok(Some(row)) => match row
            .get_str("payload")
            .ok()
            .and_then(|blob| open(&key, blob).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        {
            Some(value) => value,
            None => return HttpResponse::InternalServerError().finish(),
        },
        Ok(None) => return HttpResponse::Ok().json(Vec::<serde_json::Value>::new()),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let symbols = market_symbols_from_finance(&finance);
    if symbols.is_empty() {
        return HttpResponse::Ok().json(Vec::<serde_json::Value>::new());
    }
    let mut cursor = match state
        .market_history
        .find(doc! {"ticker":{"$in":symbols}})
        .sort(doc! {"captured_at":1})
        .limit(100000)
        .await
    {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut grouped: HashMap<String, serde_json::Value> = HashMap::new();
    while let Ok(Some(row)) = cursor.try_next().await {
        let (Ok(ticker), Ok(price), Ok(stamp), Ok(session)) = (
            row.get_str("ticker"),
            row.get_f64("price"),
            row.get_str("as_of"),
            row.get_str("session"),
        ) else {
            continue;
        };
        let key = format!("{stamp} {session}");
        let entry = grouped
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!({"as_of":stamp,"session":session,"prices":{}}));
        entry["prices"][ticker] = serde_json::json!(price);
    }
    let mut output: Vec<_> = grouped.into_values().collect();
    output.sort_by(|a, b| a["as_of"].as_str().cmp(&b["as_of"].as_str()));
    HttpResponse::Ok().json(output)
}
fn eastern_now() -> chrono::NaiveDateTime {
    let utc = Utc::now();
    let year = utc.year();
    let dst_start = second_sunday(year, 3)
        .and_hms_opt(7, 0, 0)
        .unwrap()
        .and_utc();
    let dst_end = first_sunday(year, 11)
        .and_hms_opt(6, 0, 0)
        .unwrap()
        .and_utc();
    let offset = if utc >= dst_start && utc < dst_end {
        -4
    } else {
        -5
    };
    (utc + Duration::hours(offset)).naive_utc()
}
fn first_sunday(year: i32, month: u32) -> NaiveDate {
    let first = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    first + Duration::days((7 - first.weekday().num_days_from_sunday() as i64) % 7)
}
fn second_sunday(year: i32, month: u32) -> NaiveDate {
    first_sunday(year, month) + Duration::days(7)
}
async fn collect_scheduled_quotes(
    history: Collection<Document>,
    runs: Collection<Document>,
    symbols_index: Collection<Document>,
) {
    let Ok(api_key) = std::env::var("TWELVE_DATA") else {
        return;
    };
    let now = eastern_now();
    if !matches!(
        now.weekday(),
        Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri
    ) {
        return;
    }
    let session = if now.hour() == 9 && now.minute() >= 30 && now.minute() < 40 {
        "morning"
    } else if now.hour() == 16 && now.minute() >= 20 && now.minute() < 30 {
        "close"
    } else {
        return;
    };
    let date = now.date().to_string();
    let run_filter = doc! {"date":&date,"session":session};
    if runs
        .find_one(run_filter.clone())
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    if runs.insert_one(doc!{"date":&date,"session":session,"status":"running","started_at":mongodb::bson::DateTime::now()}).await.is_err(){return}
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut cursor = match symbols_index.find(doc! {}).await {
        Ok(cursor) => cursor,
        Err(_) => return,
    };
    let mut symbols = Vec::new();
    while let Ok(Some(row)) = cursor.try_next().await {
        if let Ok(ticker) = row.get_str("ticker") {
            symbols.push(ticker.to_owned());
        }
    }
    symbols.sort();
    symbols.dedup();
    if symbols.is_empty() {
        let _ = runs
            .delete_one(doc! {"date": &date, "session": session})
            .await;
        return;
    }

    let clock = if session == "morning" {
        "09:30"
    } else {
        "16:20"
    };
    let stamp = format!("{date} {clock} ET");
    let mut saved = 0usize;
    let mut failed = false;
    for (batch_index, batch) in symbols.chunks(8).enumerate() {
        // The Basic plan allows 8 credits per minute. /price is one credit per symbol.
        if batch_index > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        }
        let mut requests = serde_json::Map::new();
        for (item_index, ticker) in batch.iter().enumerate() {
            requests.insert(
                format!("price_{item_index}"),
                serde_json::json!({"url": format!("/price?symbol={ticker}")}),
            );
        }
        let response = match client
            .post("https://api.twelvedata.com/batch")
            .header("Authorization", format!("apikey {api_key}"))
            .json(&requests)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response,
            _ => {
                failed = true;
                continue;
            }
        };
        let payload: serde_json::Value = match response.json().await {
            Ok(payload) => payload,
            Err(_) => {
                failed = true;
                continue;
            }
        };
        let Some(data) = payload.get("data").and_then(serde_json::Value::as_object) else {
            failed = true;
            continue;
        };
        let captured_at = mongodb::bson::DateTime::now();
        let mut records = Vec::new();
        for (item_index, ticker) in batch.iter().enumerate() {
            let request_key = format!("price_{item_index}");
            let Some(item) = data.get(&request_key) else {
                failed = true;
                continue;
            };
            let response = item.get("response").unwrap_or(item);
            let price = response
                .get("price")
                .and_then(|value| {
                    value
                        .as_str()
                        .and_then(|v| v.parse::<f64>().ok())
                        .or_else(|| value.as_f64())
                })
                .filter(|value| value.is_finite() && *value > 0.0);
            let Some(price) = price else {
                failed = true;
                continue;
            };
            let snapshot = match mongodb::bson::to_bson(response) {
                Ok(snapshot) => snapshot,
                Err(_) => continue,
            };
            records.push(doc! {
                "ticker": ticker,
                "price": price,
                "date": &date,
                "session": session,
                "as_of": &stamp,
                "captured_at": captured_at,
                "snapshot": snapshot
            });
        }
        if !records.is_empty() {
            match history.insert_many(records).await {
                Ok(result) => saved += result.inserted_ids.len(),
                Err(_) => failed = true,
            }
        }
    }
    let status = if saved == 0 {
        "failed"
    } else if failed {
        "partial"
    } else {
        "complete"
    };
    let _ = runs
        .update_one(
            run_filter,
            doc! {"$set": {"status": status, "as_of": &stamp, "ticker_count": saved as i64, "requested_count": symbols.len() as i64, "completed_at": mongodb::bson::DateTime::now()}},
        )
        .await;
}
#[actix_web::main]
async fn main() -> io::Result<()> {
    dotenvy::dotenv().ok();
    let uri = std::env::var("MONGODB_URI")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MONGODB_URI must be set"))?;
    let client = Client::with_uri_str(&uri).await.map_err(io::Error::other)?;
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "ledgerly".to_owned());
    let database = client.database(&db_name);
    let users: Collection<Document> = database.collection("users");
    let finance: Collection<Document> = database.collection("finance_data");
    let logins: Collection<Document> = database.collection("login_events");
    let market_history: Collection<Document> = database.collection("market_snapshots");
    let market_runs: Collection<Document> = database.collection("market_runs");
    let market_symbols: Collection<Document> = database.collection("market_symbols");
    users
        .create_index(
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    finance
        .create_index(
            IndexModel::builder()
                .keys(doc! { "user_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    logins
        .create_index(
            IndexModel::builder()
                .keys(doc! { "user_id": 1, "logged_at": -1 })
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    market_history
        .create_index(
            IndexModel::builder()
                .keys(doc! {"ticker":1,"date":1,"session":1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    market_runs
        .create_index(
            IndexModel::builder()
                .keys(doc! {"date":1,"session":1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    market_symbols
        .create_index(
            IndexModel::builder()
                .keys(doc! {"ticker": 1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await
        .map_err(io::Error::other)?;
    let scheduled_history = market_history.clone();
    let scheduled_runs = market_runs.clone();
    let scheduled_symbols = market_symbols.clone();
    tokio::spawn(async move {
        loop {
            collect_scheduled_quotes(
                scheduled_history.clone(),
                scheduled_runs.clone(),
                scheduled_symbols.clone(),
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
    let state = web::Data::new(AppState {
        users,
        finance,
        logins,
        sessions: Mutex::new(HashMap::new()),
        market_history,
        market_symbols,
    });
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);
    println!("Ledgerly listening at http://127.0.0.1:{port}");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(register)
            .service(login)
            .service(me)
            .service(rotate_recovery)
            .service(recover_password)
            .service(admin_users)
            .service(delete_user)
            .service(logout)
            .service(get_finance)
            .service(save_finance)
            .service(get_market_history)
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
