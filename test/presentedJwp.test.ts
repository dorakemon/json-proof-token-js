import {
  IssuedJwp,
  Jwk,
  JwpProofAlgorithm,
  JwpSerializationType,
  PresentedJwp,
  SupportedKeyType,
} from "json_proof_token_wasm";
import { afterAll, describe, expect, it } from "vitest";

describe("PresentedJwp functionality", () => {
  const jwk = Jwk.generate(SupportedKeyType.BLS12381G2);

  afterAll(() => {
    jwk.free();
  });

  it("should create and verify a PresentedJwp", () => {
    const claims = {
      sub: "1234567890",
      name: "John Doe",
      admin: true,
    };
    const issuedJwp = new IssuedJwp(
      jwk,
      JwpProofAlgorithm.Bbs,
      "https://example.com",
      JSON.stringify(claims),
    );

    const audience = "https://example.com";
    const nonce = "nonce_value";
    const undisclosedPaths = ["name", "admin"];
    const presentedJwp = new PresentedJwp(
      jwk,
      issuedJwp,
      undisclosedPaths,
      audience,
      nonce,
    );
    const encodedPresented = presentedJwp.encode(JwpSerializationType.Compact);
    expect(encodedPresented).toBeDefined();

    const publicKey = jwk.to_public();
    const result = PresentedJwp.verify(
      publicKey,
      JwpSerializationType.Compact,
      encodedPresented,
    );
    expect(result).toBe(true);

    publicKey.free();
    presentedJwp.free();
    issuedJwp.free();
  });
});
