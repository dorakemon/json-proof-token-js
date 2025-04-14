use jsonprooftoken::jwk::{key as internal_jwk, types::KeyPairSubtype};
use serde::{Deserialize, Serialize};
use serde_json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum SupportedKeyType {
    BLS12381G2,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Jwk {
    #[wasm_bindgen(skip)]
    pub(crate) inner: internal_jwk::Jwk,
}

#[wasm_bindgen]
impl Jwk {
    #[wasm_bindgen(constructor)]
    pub fn new(jwk_json: &str) -> Result<Jwk, JsValue> {
        let inner: internal_jwk::Jwk = serde_json::from_str(jwk_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JWK JSON: {}", e)))?;
        Ok(Jwk { inner })
    }

    #[wasm_bindgen]
    pub fn generate(key_type: SupportedKeyType) -> Result<Jwk, JsValue> {
        let jwk = match key_type {
            SupportedKeyType::BLS12381G2 => {
                internal_jwk::Jwk::generate(KeyPairSubtype::BLS12381G2Sha256).map_err(|e| {
                    JsValue::from_str(&format!("Failed to generate BLS12-381 JWK: {}", e))
                })?
            }
        };
        Ok(Jwk { inner: jwk })
    }

    fn from_internal_jwk(jwk: internal_jwk::Jwk) -> Self {
        Jwk { inner: jwk }
    }

    #[wasm_bindgen]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.inner).unwrap_or_else(|_| "{}".to_string())
    }

    #[wasm_bindgen]
    pub fn to_public(&self) -> Result<Jwk, JsValue> {
        let public_jwk = self
            .inner
            .to_public()
            .ok_or_else(|| JsValue::from_str("Failed to convert to public key"))?;
        Ok(Jwk::from_internal_jwk(public_jwk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_basic_functionality() {
        let jwk = Jwk::generate(SupportedKeyType::BLS12381G2).unwrap();
        let jwk_json = jwk.to_json();
        assert!(!jwk_json.is_empty());
        assert_ne!(jwk_json, "{}");
        assert!(jwk_json.contains("\"kty\""));
        assert!(jwk_json.contains("\"crv\""));
        assert!(jwk_json.contains("\"x\""));
        assert!(jwk_json.contains("\"y\""));

        let public_jwk = jwk.to_public().unwrap();
        let public_json = public_jwk.to_json();
        assert!(public_json.contains("\"x\""));
        assert!(public_json.contains("\"y\""));
        assert!(!public_json.contains("\"d\""));
    }

    #[test]
    fn test_jwk_from_json() {
        let jwk = Jwk::generate(SupportedKeyType::BLS12381G2).unwrap();
        let jwk_json = jwk.to_json();
        let parsed_jwk = Jwk::new(&jwk_json).unwrap();
        assert_eq!(parsed_jwk.to_json(), jwk_json);
    }
}
