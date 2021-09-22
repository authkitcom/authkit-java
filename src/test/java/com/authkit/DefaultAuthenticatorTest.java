package com.authkit;


import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultAuthenticatorTest {

    private static final Gson GSON = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy
        .LOWER_CASE_WITH_UNDERSCORES).create();

    private Config config;
    private DefaultAuthenticator unit;
    private static final String ISSUER = "http://localhost:9996";
    private static final String AUDIENCE = "test-audience";

    @BeforeEach
    public void setUp() {

        config = new Config();

        config.setIssuer(ISSUER);
        config.setAudience(AUDIENCE);

        unit = new DefaultAuthenticator(config);
    }

    @ParameterizedTest
    @MethodSource("userData")
    public void authenticate(String sub, Map<String, Object> additionalClaims, AuthkitPrincipal expected) throws UnsupportedEncodingException {

        HttpClient client = HttpClient.create();

        var uri = String.format("http://localhost:9996/authorize?sub=%s&json=true", sub);

        if (additionalClaims != null) {
            uri = uri + "&additional_claims=" + URLEncoder.encode(GSON.toJson(additionalClaims), "UTF-8");
        }

        var resp = client.get()
            .uri(uri)
            .responseSingle((r, b) -> {
                if (r.status().code() == 200) {
                    return b.asInputStream();
                } else {
                    throw new AuthkitException("Unable to get code from server");
                }
            }).map(i -> GSON.fromJson(new InputStreamReader(i), Map.class))
            .block();

        String code = (String) resp.get("code");

        var tokenResp = client.post().uri(ISSUER + "/oauth/token").sendForm((r,f) -> {
                f.attr("code", code);
                f.attr("audience", AUDIENCE);
                f.attr("redirect_uri", "http://localhost:8080");
        }).responseSingle((r, b) -> {
            if (r.status().code() == 200) {
                return b.asInputStream();
            } else {
                throw new AuthkitException("Unable to get retrieve token from server");
            }
        }).map(i -> GSON.fromJson(new InputStreamReader(i), Map.class)).block();

        String accessToken = (String) tokenResp.get("access_token");

        AuthkitPrincipal got = Mono.from(unit.authenticate(accessToken)).block();

        assertThat(got).isEqualTo(expected);
    }

    public static Stream<Arguments> userData() {

        var pa = new AuthkitPrincipal();

        pa.setSub("a");
        pa.setIssuer(ISSUER);
        pa.setAudience(AUDIENCE);
        pa.setFamilyName("LastA");
        pa.setGivenName("FirstA");
        pa.setEmail("emailA@domain.com");

        var pb = new AuthkitPrincipal();

        pb.setSub("b");
        pb.setIssuer(ISSUER);
        pb.setAudience(AUDIENCE);

        pb.setEmail("email@domain.com");
        pb.setEmailVerified(true);
        pb.setFamilyName("Family");
        pb.setGender("M");
        pb.setGivenName("Given");
        pb.setGroups(Set.of("group1", "group2"));
        pb.setMiddleName("E");
        pb.setClaimName("Given E Family");
        pb.setNickname("nick");
        pb.setPermissions(Set.of("permission1", "permission2"));
        pb.setPhoneNumber("360-555-1212");
        pb.setPhoneNumberVerified(true);
        pb.setPreferredUsername("gfamily");
        pb.setRoles(Set.of("role1", "role2"));
        pb.setUpdatedAt(10000l);
        pb.setMetadata(Map.of(
            "um1", "umv1",
            "um2", 12345678d
        ));

        var pa2 = new AuthkitPrincipal();

        pa2.setSub("a");
        pa2.setIssuer(ISSUER);
        pa2.setAudience(AUDIENCE);
        pa2.setFamilyName("LastA");
        pa2.setGivenName("FirstA");
        pa2.setEmail("emailA@domain.com");
        pa2.setExtraClaims(Map.of("client", "test-client"));

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("claims", Map.of("client", "test-client"));
        additionalClaims.put("claims_in_access_token", new String[]{"client"});
        additionalClaims.put("claims_in_userinfo", new String[]{"client"});

        return Stream.of(
            Arguments.of("a", null, pa),
            Arguments.of("b", null, pb),
            Arguments.of("a", additionalClaims, pa2)
        );
    }
}
