import {
  IssuedJwp,
  Jwk,
  JwpProofAlgorithm,
  JwpSerializationType,
  SupportedKeyType,
} from "json_proof_token_wasm";
import { afterAll, describe, expect, it } from "vitest";

describe("Jwk functionality", () => {
  const jwk = Jwk.generate(SupportedKeyType.BLS12381G2);
  const claims = {
    iss: "https://example.com/issuer",
    sub: "1234567890",
    name: "John Doe",
    iat: 1516239022,
    address: {
      street_address: "123 Main St",
      locality: "Anytown",
      region: "CA",
      postal_code: "12345",
      country: "USA",
    },
  };

  afterAll(() => {
    jwk.free();
  });

  it("should generate a IssuedJWP", () => {
    const issuedJwp = new IssuedJwp(
      jwk,
      JwpProofAlgorithm.Bbs,
      "https://example.com/issuer",
      JSON.stringify(claims),
    );
    const rawJwp = issuedJwp.encode(JwpSerializationType.Compact);
    expect(rawJwp).toBeDefined();
    expect(rawJwp.split(".").length).toBe(3);
    issuedJwp.free();
  });

  it("should verify a IssuedJWP", () => {
    const issuedJwp = new IssuedJwp(
      jwk,
      JwpProofAlgorithm.Bbs,
      "https://example.com/issuer",
      JSON.stringify(claims),
    );
    const rawJwp = issuedJwp.encode(JwpSerializationType.Compact);
    const jwkPublic = jwk.to_public();
    const result = IssuedJwp.verify(
      jwkPublic,
      JwpSerializationType.Compact,
      rawJwp,
    );
    expect(result).toBe(true);
    issuedJwp.free();
    jwkPublic.free();
  });
});
