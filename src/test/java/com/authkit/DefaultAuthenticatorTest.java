package com.authkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

public class DefaultAuthenticatorTest {

  private Config config;
  private DefaultAuthenticator unit;

  @BeforeEach
  public void setUp() {

    config = new Config();

    config.setIssuer(TestConstants.ISSUER);
    config.setAudience(TestConstants.AUDIENCE);

    unit = new DefaultAuthenticator(config);
  }

  @ParameterizedTest
  @MethodSource("userData")
  public void authenticate(
      String sub, Map<String, Object> additionalClaims, AuthkitPrincipal expected)
      throws UnsupportedEncodingException {

    HttpClient client = HttpClient.create();

    var uri = String.format("http://localhost:9996/authorize?sub=%s&json=true", sub);

    if (additionalClaims != null) {
      uri =
          uri
              + "&additional_claims="
              + URLEncoder.encode(TestConstants.GSON.toJson(additionalClaims), "UTF-8");
    }

    var resp =
        client
            .get()
            .uri(uri)
            .responseSingle(
                (r, b) -> {
                  if (r.status().code() == 200) {
                    return b.asInputStream();
                  } else {
                    throw new AuthkitException("Unable to get code from server");
                  }
                })
            .map(i -> TestConstants.GSON.fromJson(new InputStreamReader(i), Map.class))
            .block();

    String code = (String) resp.get("code");

    var tokenResp =
        client
            .post()
            .uri(TestConstants.ISSUER + "/oauth/token")
            .sendForm(
                (r, f) -> {
                  f.attr("grant_type", "authorization_code")
                      .attr("code", code)
                      .attr("audience", TestConstants.AUDIENCE)
                      .attr("redirect_uri", "http://localhost:8080");
                })
            .responseSingle(
                (r, b) -> {
                  if (r.status().code() == 200) {
                    return b.asInputStream();
                  } else {
                    throw new AuthkitException("Unable to get token from server");
                  }
                })
            .map(i -> TestConstants.GSON.fromJson(new InputStreamReader(i), Map.class))
            .block();

    String accessToken = (String) tokenResp.get("access_token");

    AuthkitPrincipal got = Mono.from(unit.authenticate(accessToken)).block();

    assertThat(got).isEqualTo(expected);
  }

  public static Stream<Arguments> userData() {

    var pa = new AuthkitPrincipal();

    pa.setSub("a");
    pa.setIssuer(TestConstants.ISSUER);
    pa.setAudience(TestConstants.AUDIENCE);
    pa.setFamilyName("LastA");
    pa.setGivenName("FirstA");
    pa.setEmail("emailA@domain.com");

    var pb = new AuthkitPrincipal();

    pb.setSub("b");
    pb.setIssuer(TestConstants.ISSUER);
    pb.setAudience(TestConstants.AUDIENCE);

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
    pb.setMetadata(Map.of("um1", "umv1", "um2", 12345678d));

    var pa2 = new AuthkitPrincipal();

    pa2.setSub("a");
    pa2.setIssuer(TestConstants.ISSUER);
    pa2.setAudience(TestConstants.AUDIENCE);
    pa2.setFamilyName("LastA");
    pa2.setGivenName("FirstA");
    pa2.setEmail("emailA@domain.com");
    pa2.setExtraClaims(Map.of("client", "test-client"));

    Map<String, Object> additionalClaims = new HashMap<>();
    additionalClaims.put("claims", Map.of("client", "test-client"));
    additionalClaims.put("claims_in_access_token", new String[] {"client"});
    additionalClaims.put("claims_in_userinfo", new String[] {"client"});

    return Stream.of(
        Arguments.of("a", null, pa),
        Arguments.of("b", null, pb),
        Arguments.of("a", additionalClaims, pa2));
  }
}
