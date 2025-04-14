use jsonprooftoken::{
    encoding::SerializationType,
    jpa::algs::ProofAlgorithm,
    jpt::claims::JptClaims,
    jwp::{
        header::IssuerProtectedHeader,
        issued::{JwpIssued, JwpIssuedBuilder, JwpIssuedDecoder},
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::jwk::Jwk;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct IssuedJwp {
    #[wasm_bindgen(skip)]
    pub(crate) inner: JwpIssued,
}

#[wasm_bindgen]
pub enum JwpSerializationType {
    Compact,
    Json,
}

impl From<JwpSerializationType> for SerializationType {
    fn from(value: JwpSerializationType) -> Self {
        match value {
            JwpSerializationType::Compact => SerializationType::COMPACT,
            JwpSerializationType::Json => SerializationType::JSON,
        }
    }
}

#[wasm_bindgen]
pub enum JwpProofAlgorithm {
    Bbs,
}

impl From<JwpProofAlgorithm> for ProofAlgorithm {
    fn from(value: JwpProofAlgorithm) -> Self {
        match value {
            JwpProofAlgorithm::Bbs => ProofAlgorithm::BBS,
        }
    }
}

#[wasm_bindgen]
impl IssuedJwp {
    #[wasm_bindgen(constructor)]
    pub fn new(
        jwk: &Jwk,
        alg: JwpProofAlgorithm,
        issuer: &str,
        claims_json: &str,
    ) -> Result<IssuedJwp, JsValue> {
        let issued_header = IssuerProtectedHeader::new(ProofAlgorithm::from(alg));
        let custom_claims = match serde_json::from_str::<serde_json::Value>(claims_json) {
            Ok(claims) => claims,
            Err(err) => {
                return Err(JsError::new(&format!("Failed to parse claims JSON: {}", err)).into())
            }
        };
        let mut jpt_claims = JptClaims::new();
        jpt_claims.set_iss(issuer.to_owned());
        jpt_claims.set_claim(None, custom_claims, true);
        let issued_jwp = JwpIssuedBuilder::new(issued_header, jpt_claims)
            .build(&jwk.inner)
            .unwrap();
        Ok(IssuedJwp { inner: issued_jwp })
    }

    #[wasm_bindgen]
    pub fn encode(&self, serialization_type: JwpSerializationType) -> Result<String, JsValue> {
        self.inner
            .encode(serialization_type.into())
            .map_err(|e| JsValue::from_str(&format!("Failed to encode JWP: {}", e)))
    }

    #[wasm_bindgen]
    pub fn verify(
        jwk: &Jwk,
        serialization_type: JwpSerializationType,
        jwp_string: &str,
    ) -> Result<bool, JsValue> {
        JwpIssuedDecoder::decode(jwp_string, serialization_type.into())
            .map_err(|e| JsValue::from_str(&format!("Failed to decode JWP: {}", e)))
            .unwrap()
            .verify(&jwk.inner.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to verify JWP: {}", e)))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::SupportedKeyType;

    #[test]
    fn test_issued_jwp_basic_functionality() {
        let jwk = Jwk::generate(SupportedKeyType::BLS12381G2).unwrap();
        let claims_json = r#"{
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts",
                "ciao": [
                    {"u1": "value1"},
                    {"u2": "value2"}
                ]
            },
            "name": "John Doe"
        }"#;

        // Create IssuedJWP
        let issued_jwp = IssuedJwp::new(
            &jwk,
            JwpProofAlgorithm::Bbs,
            "https://issuer.example",
            claims_json,
        )
        .unwrap();

        // Encode JWP
        let encoded = issued_jwp.encode(JwpSerializationType::Compact).unwrap();
        assert!(!encoded.is_empty());
        println!("Encoded JWP: {}", encoded);

        // Verify JWP
        let public_jwk = jwk.to_public().unwrap();
        let verified =
            IssuedJwp::verify(&public_jwk, JwpSerializationType::Compact, &encoded).unwrap();
        assert!(verified);
    }
}
