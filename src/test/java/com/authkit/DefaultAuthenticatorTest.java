package com.authkit;


import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.netty.handler.codec.http.HttpResponseStatus;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.netty.http.client.HttpClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultAuthenticatorTest {

    private static final Gson GSON = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy
        .LOWER_CASE_WITH_UNDERSCORES).create();

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

        HttpClient client = HttpClient.create();

        var resp = client.get()
            .uri("http://localhost:9996/authorize?sub=a&json=true")
            .responseSingle((r, b) -> {
                if (r.status().code() == 200) {
                    return b.asString();
                } else {
                    throw new AuthkitException("Unable to get code from server");
                }
            }).map(s -> GSON.fromJson(s, Map.class))
            .block();

        String code = (String) resp.get("code");

        var tokenResp = client.post().uri("http://localhost:9996/oauth/token").sendForm((r,f) -> {
                f.attr("code", code);
                f.attr("audience", audience);
                f.attr("redirect_uri", "http://localhost:8080");
        }).responseSingle((r, b) -> {
            if (r.status().code() == 200) {
                return b.asString();
            } else {
                throw new AuthkitException("Unable to get code from server");
            }
        }).map(s -> GSON.fromJson(s, Map.class)).block();

        String accessToken = (String) tokenResp.get("access_token");

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