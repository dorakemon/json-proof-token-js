import { Jwk, SupportedKeyType } from "json_proof_token_wasm";
import { describe, expect, it } from "vitest";

describe("Jwk functionality", () => {
  it("should generate a JWK", () => {
    const jwk = Jwk.generate(SupportedKeyType.BLS12381G2);
    const jwkRawJson = jwk.to_json();
    const jwkJson = JSON.parse(jwkRawJson);
    expect(jwkJson).toHaveProperty("kty", "EC");
    expect(jwkJson).toHaveProperty("crv", "BLS12381G2");
    expect(jwkJson).toHaveProperty("x");
    expect(jwkJson).toHaveProperty("y");
    expect(jwkJson).toHaveProperty("d");

    const jwkPublic = jwk.to_public();
    const jwkPublicRawJson = jwkPublic.to_json();
    const jwkPublicJson = JSON.parse(jwkPublicRawJson);
    expect(jwkPublicJson).toHaveProperty("kty", "OKP");
    expect(jwkPublicJson).toHaveProperty("crv", "BLS12381G2");
    expect(jwkPublicJson).toHaveProperty("x");
    expect(jwkPublicJson).toHaveProperty("y");
    expect(jwkPublicJson).not.toHaveProperty("d");
  });

  it("should load a JWK", () => {
    const sampleJwk = {
      kty: "EC",
      crv: "BLS12381G2",
      x: "Dr6m2d5He3Z4f-bIzK4nZD9SCnUMulR1xzb0q1EUzTaGlMHbsDUQWlXVtIpIvzOJC2w_fl67bUka3XrBaGTdWQJAYbs38YY2lIKgerh2-rfd-PqvbJHBvOy2lklpNEYz",
      y: "CUYzAkHZouJa5_YpbQH2PKejm0TCWb-RQuy2jsPNvzHOb1keYUD64Lxmsz-JJvLJBg71vHwY6ULDSPfMkmv5wEv6homfqTedkVG360eKFlct0caDvrG8eztrQg7cDQt6",
      d: "BiTr-TBDDmxHFgkngTnl41gsZYgxaQj2bIiHW8a455s",
    };
    const jwk = new Jwk(JSON.stringify(sampleJwk));
    const rawJwkJson = jwk.to_json();
    const jwkJson = JSON.parse(rawJwkJson);
    expect(jwkJson).toHaveProperty("kty", "EC");
    expect(jwkJson).toHaveProperty("crv", "BLS12381G2");
    expect(jwkJson).toHaveProperty("x", sampleJwk.x);
    expect(jwkJson).toHaveProperty("y", sampleJwk.y);
    expect(jwkJson).toHaveProperty("d", sampleJwk.d);
  });
});
