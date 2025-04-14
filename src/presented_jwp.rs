use jsonprooftoken::{
    jpa::algs::PresentationProofAlgorithm,
    jwp::{
        header::PresentationProtectedHeader,
        presented::{JwpPresented, JwpPresentedBuilder, JwpPresentedDecoder},
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{
    issued_jwp::{IssuedJwp, JwpSerializationType},
    jwk::Jwk,
};

#[wasm_bindgen]
pub enum JwpPresentationProofAlgorithm {
    Bbs,
}

impl From<JwpPresentationProofAlgorithm> for PresentationProofAlgorithm {
    fn from(value: JwpPresentationProofAlgorithm) -> Self {
        match value {
            JwpPresentationProofAlgorithm::Bbs => PresentationProofAlgorithm::BBS,
        }
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct PresentedJwp {
    pub(crate) inner: JwpPresented,
}

#[wasm_bindgen]
impl PresentedJwp {
    #[wasm_bindgen(constructor)]
    pub fn new(
        jwk: &Jwk,
        issued_jwp: &IssuedJwp,
        undisclosed_paths: Vec<String>,
        audience: Option<String>,
        nonce: Option<String>,
    ) -> Result<PresentedJwp, JsValue> {
        // Create presentation header
        let mut presentation_header = PresentationProtectedHeader::new(
            issued_jwp.inner.get_issuer_protected_header().alg().into(),
        );
        if let Some(aud) = audience {
            presentation_header.set_aud(Some(aud));
        }
        if let Some(n) = nonce {
            presentation_header.set_nonce(Some(n));
        }

        // Start building the presented JWP
        let mut builder_obj = JwpPresentedBuilder::new(&issued_jwp.inner);
        let mut builder = builder_obj.set_presentation_protected_header(presentation_header);
        // Add undisclosed paths
        for path in undisclosed_paths {
            match builder.set_undisclosed(&path) {
                Ok(updated_builder) => {
                    builder = updated_builder;
                }
                Err(err) => {
                    return Err(JsValue::from_str(&format!(
                        "Failed to set undisclosed path '{}': {}",
                        path, err
                    )));
                }
            }
        }
        // Build the presented JWP
        let presented_jwp = match builder.build(&jwk.inner.to_public().unwrap()) {
            Ok(jwp) => jwp,
            Err(err) => {
                return Err(JsValue::from_str(&format!(
                    "Failed to build presented JWP: {}",
                    err
                )));
            }
        };

        Ok(PresentedJwp {
            inner: presented_jwp,
        })
    }

    #[wasm_bindgen]
    pub fn encode(&self, serialization_type: JwpSerializationType) -> Result<String, JsValue> {
        match self.inner.encode(serialization_type.into()) {
            Ok(encoded) => Ok(encoded),
            Err(err) => Err(JsValue::from_str(&format!("Encoding error: {}", err))),
        }
    }

    #[wasm_bindgen]
    pub fn verify(
        jwk: &Jwk,
        serialization_type: JwpSerializationType,
        jwp_string: &str,
    ) -> Result<bool, JsValue> {
        JwpPresentedDecoder::decode(&jwp_string, serialization_type.into())
            .unwrap()
            .verify(&jwk.inner.to_public().unwrap())
            .map_err(|e| JsValue::from_str(&format!("Failed to verify presented JWP: {}", e)))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod tests {
        use crate::{
            issued_jwp::{IssuedJwp, JwpProofAlgorithm, JwpSerializationType},
            jwk::{Jwk, SupportedKeyType},
            presented_jwp::PresentedJwp,
        };

        #[test]
        fn test_presented_jwp_basic_functionality() {
            let jwk = Jwk::generate(SupportedKeyType::BLS12381G2).unwrap();
            let issued_jwp = IssuedJwp::new(
                &jwk,
                JwpProofAlgorithm::Bbs,
                "https://example.com",
                r#"{"sub": "1234567890", "name": "John Doe", "admin": true}"#,
            )
            .unwrap();

            let audience = Some("https://example.com".to_string());
            let nonce = Some("nonce_value".to_string());
            let undisclosed_paths = ["name".to_string(), "admin".to_string()].to_vec();
            let presented_jwp =
                PresentedJwp::new(&jwk, &issued_jwp, undisclosed_paths, audience, nonce).unwrap();

            let encoded = presented_jwp.encode(JwpSerializationType::Compact).unwrap();
            assert!(!encoded.is_empty());

            let verified = PresentedJwp::verify(
                &jwk.to_public().unwrap(),
                JwpSerializationType::Compact,
                &encoded,
            )
            .unwrap();
            assert!(verified);
        }
    }
}
