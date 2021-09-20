package com.authkit;


import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultAuthenticatorTest {

    private Config config;
    private DefaultAuthenticator unit;
    private final String audience = "test-audience";

    @BeforeEach
    public void setUp() {

        config = new Config();

        config.setIssuer("http://localhost:9996");
        config.setAudience(audience);

        unit = new DefaultAuthenticator(config);
    }

    @Test
    public void initial() {

        assertThat(unit.openIdConfiguration).isNotNull();
        assertThat(unit.jwks).isNotNull();
        assertThat(unit.publicKey).isNotNull();
        assertThat(unit.jwtParser).isNotNull();
    }

    @Test
    public void authenticate() {

        HttpResponse<JsonNode> resp = Unirest.get("http://localhost:9996/authorize?sub=a&json=true").asJson();

        if (resp.getStatus() != 200) {
            throw new RuntimeException("Authorize status code: " + resp.getStatus());
        }

        String code = resp.getBody().getObject().getString("code");

        HttpResponse<JsonNode> tokenResp = Unirest.post("http://localhost:9996/oauth/token")
                .field("code", code)
                .field("audience", audience)
                .field("redirect_uri", "http://localhost:8080")
                .asJson();

        if (tokenResp.getStatus() != 200) {
            throw new RuntimeException("Token status code: " + resp.getStatus());
        }

        String accessToken = tokenResp.getBody().getObject().getString("access_token");

        AuthkitPrincipal got = unit.authenticate(accessToken);

        assertThat(got).isNotNull();
        assertThat(got.getSubject()).isEqualTo("a");
        assertThat(got.getAudience()).isEqualTo(audience);
        assertThat(got.getEmail()).isNotEmpty();
        assertThat(got.getFamilyName()).isNotEmpty();
        assertThat(got.getGivenName()).isNotEmpty();
        assertThat(got.getIssuer()).isEqualTo("http://localhost:9996");
        assertThat(got.getPermissions()).hasSize(2);
        assertThat(got.getRoles()).hasSize(2);

    }
}