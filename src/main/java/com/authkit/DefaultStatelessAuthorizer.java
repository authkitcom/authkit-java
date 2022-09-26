package com.authkit;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

public class DefaultStatelessAuthorizer implements StatelessAuthorizer {

  private final String authorizeEndpoint;
  private final String tokenEndpoint;

  private static final String ISSUER = "http://localhost:9996";

  // TODO - One day this should be shared among instances (including authenitcator)
  private final HttpClient client;

  private static final Gson GSON =
      new GsonBuilder()
          .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
          .create();

  public DefaultStatelessAuthorizer(Config config) {
    var issuer = config.getIssuer();

    authorizeEndpoint = issuer + "/authorize";
    tokenEndpoint = issuer + "/oauth/token";

    this.client = HttpClient.create();
  }

  @Override
  public Mono<String> buildAuthorizeUrl(AuthorizeParameters params) {

    StringBuilder sb = new StringBuilder();

    sb.append(authorizeEndpoint);
    sb.append("?response_type=code&client_id=");
    sb.append(requireURLEncoded(params.getClientId(), "clientId"));
    sb.append("&redirect_uri=");
    sb.append(requireURLEncoded(params.getRedirectUri(), "redirectUri"));
    if (params.getScope() != null) {
      sb.append("&scope=");
      sb.append(urlEncode(String.join(" ", params.getScope())));
    }
    if (params.getNonce() != null) {
      sb.append("&nonce=");
      sb.append(urlEncode(params.getNonce()));
    }
    if (params.getCodeChallenge() != null) {
      sb.append("&code_challenge");
      sb.append(urlEncode(params.getNonce()));
      sb.append("&code_challenge_method");
      sb.append(requireURLEncoded(params.getNonce(), "codeChallengeMethod"));
    }
    if (params.getPrompt() != null) {
      sb.append("&prompt=");
      sb.append(urlEncode(params.getPrompt()));
    }

    return Mono.just(sb.toString());
  }

  @Override
  public Mono<Tokens> fetchTokens(FetchTokensParameters params) {

    return client
        .post()
        .uri(tokenEndpoint)
        .sendForm(
            (r, f) -> {
              f.attr("grant_type", "authorization_code")
                  .attr("code", params.getCode())
                  .attr("redirect_uri", params.getRedirectUri());

              if (params.getCodeVerifier() != null) {
                f.attr("code_verifier", params.getCodeVerifier());
              }
            })
        .responseSingle(
            (r, b) -> {
              if (r.status().code() == 200) {
                return b.asInputStream();
              } else {
                throw new AuthkitException("Unable to get token from server");
              }
            })
        .map(
            i -> {
              try {
                return GSON.fromJson(new InputStreamReader(i), Tokens.class);
              } finally {
                Util.close(i);
              }
            });
  }

  private String requireURLEncoded(String input, String label) {
    return urlEncode(Objects.requireNonNull(input, label));
  }

  private String urlEncode(String input) {
    return URLEncoder.encode(input, StandardCharsets.UTF_8);
  }
}
