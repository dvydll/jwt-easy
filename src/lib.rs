use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

pub trait Constructible<T> {
  fn new(params: T) -> Self;
}
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JwtOptions {
  secret: String,
  expires_in: u64,
}
impl Default for JwtOptions {
  fn default() -> Self {
    Self {
      secret: "$3creT".to_string(),
      expires_in: 60 * 60 * 1000, // 1 hour
    }
  }
}
impl Constructible<(String, u64)> for JwtOptions {
  fn new(params: (String, u64)) -> Self {
    Self { secret: params.0, expires_in: params.1 }
  }
}
#[wasm_bindgen]
impl JwtOptions {
  // static methods
  #[wasm_bindgen(constructor)]
  pub fn new(secret: String, expires_in: u64) -> Self {
    Self { secret, expires_in }
  }
  // instance methods
  pub fn get_days(&self) -> u64 {
    self.expires_in / 24 / 60 / 60 / 1000
  }
  pub fn get_hours(&self) -> u64 {
    self.expires_in / 60 / 60 / 1000
  }
  pub fn get_minutes(&self) -> u64 {
    self.expires_in / 60 / 1000
  }
  pub fn get_seconds(&self) -> u64 {
    self.expires_in / 1000
  }
}

/// 📌 Crea un JWT personalizado
///
/// ### Arguments
///
/// - `payload` - Un objeto JSON con los datos a incluir en el JWT.
/// - `options` - Un objeto JSON con opciones como la clave secreta y la duración.
///
/// ### Returns
///
/// - Devuelve un `String` con el JWT generado.
/// - En caso de error, devuelve un `JsValue` con el mensaje de error.
///
/// ```typescript
/// export function create_jwt(payload: Record<string, any>, options: JwtOptions): string;
/// ```
#[wasm_bindgen]
pub fn create_jwt(
  payload: JsValue,
  options: JsValue,
) -> Result<String, JsValue> {
  let deserialized_payload: Value = from_value(payload).map_err(|err| {
    JsValue::from_str(&format!("Failed to parse payload: {err}"))
  })?;
  let jwt_options: JwtOptions = from_value(options).map_err(|err| {
    JsValue::from_str(&format!("Failed to parse options: {err}"))
  })?;

  // Crea los claims con el payload personalizado
  let claims = Claims::with_custom_claims(
    deserialized_payload,
    Duration::from_hours(jwt_options.get_hours()),
  );

  // Genera el JWT
  let key = HS256Key::from_bytes(jwt_options.secret.as_bytes());
  key
    .authenticate(claims)
    .map_err(|err| JsValue::from_str(&format!("Failed to create JWT: {err}")))
}

/// 📌 Verifica el JWT y devuelve el payload decodificado
///
/// ### Arguments
///
/// - `token` - Una cadena con el token JWT.
/// - `secret` - El secreto de la clave de autenticación.
///
/// ### Returns
///
/// - Devuelve un `Map<string, any>` con el payload deserializado.
/// - En caso de error, devuelve un `JsValue` con el mensaje de error.
///
/// ```typescript
/// export function verify_jwt(token: string, secret: string): Map<string, any>;
/// ```
#[wasm_bindgen]
pub fn verify_jwt(token: &str, secret: &str) -> Result<JsValue, JsValue> {
  if secret.is_empty() {
    return Err(JsValue::from_str("Secret key cannot be empty"));
  }

  let key = HS256Key::from_bytes(secret.as_bytes());
  let claims = key.verify_token::<Value>(token, None).map_err(|err| {
    JsValue::from_str(&format!("Failed to verify token: {err}"))
  })?;

  // Convierte el payload personalizado de vuelta a JsValue
  to_value(&claims.custom).map_err(|err| {
    JsValue::from_str(&format!("Failed to serialize payload: {err}"))
  })
}
