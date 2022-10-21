package com.authkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URISyntaxException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

public class DefaultStatelessAuthorizerTest {

  private DefaultStatelessAuthorizer unit;

  @BeforeEach
  public void setUp() {

    var config = new Config();

    config.setIssuer(TestConstants.ISSUER);

    unit = new DefaultStatelessAuthorizer(config);
  }

  @Test
  public void buildAuthorizeUrl_minimal() {

    var params = new AuthorizeParameters();
    params.setClientId("test client id");
    params.setRedirectUri("http://somehost:1234?foo=bar&baz=blah#frag");

    var got = unit.buildAuthorizeUrl(params).block();

    assertThat(got)
        .isEqualTo(
            "http://localhost:9996/authorize?response_type=code&client_id=test+client+id&redirect_uri=http%3A%2F%2Fsomehost%3A1234%3Ffoo%3Dbar%26baz%3Dblah%23frag");
  }

  @Test
  public void buildAuthorizeUrl_full() {

    var params = new AuthorizeParameters();
    params.setClientId("test client id");
    params.setRedirectUri("http://somehost:1234?foo=bar&baz=blah#frag");
    params.setNonce("test nonce");
    params.setCodeChallenge("code challenge");
    params.setCodeChallengeMethod("S256");
    params.setScope(new String[] {"scope1", "scope2"});
    params.setState("test state value");
    params.setPrompt("none");

    var got = unit.buildAuthorizeUrl(params).block();

    assertThat(got)
        .isEqualTo(
            "http://localhost:9996/authorize?response_type=code&client_id=test+client+id&redirect_uri=http%3A%2F%2Fsomehost%3A1234%3Ffoo%3Dbar%26baz%3Dblah%23frag&scope=scope1+scope2&nonce=test+nonce&code_challenge=code+challenge&code_challenge_method=S256&prompt=none");
  }

  @Test
  public void authorizeAndGetTokens() throws URISyntaxException {

    var redirectUri = "http://somehost";

    var params = new AuthorizeParameters();
    params.setClientId("test-client");
    params.setRedirectUri(redirectUri);
    var verifier = params.generatePkce();
    params.generateNonce();
    params.setScope(new String[] {"scope1", "scope2"});
    params.setState("test-state");
    params.setPrompt("none");

    HttpClient client = HttpClient.create();

    var uri = unit.buildAuthorizeUrl(params).block() + "&sub=a";

    var resp =
        client
            .get()
            .uri(uri)
            .responseSingle(
                (r, b) -> {
                  if (r.status().code() == 302) {
                    return Mono.just(r.responseHeaders().get("Location"));
                  } else {
                    throw new AuthkitException("Unable to get code from server");
                  }
                })
            .block();

    var code = resp.replace(redirectUri + "?code=", "");

    var tokenParams = new FetchTokensParameters();

    tokenParams.setClientId("test");
    tokenParams.setCode(code);
    tokenParams.setRedirectUri(redirectUri);
    tokenParams.setCodeVerifier(verifier);

    var tokens = unit.fetchTokens(tokenParams).block();

    assertThat(tokens.getAccessToken()).isNotEmpty();
    assertThat(tokens.getIdToken()).isNotEmpty();
    assertThat(tokens.getExpiresIn()).isGreaterThan(0);
  }
}
