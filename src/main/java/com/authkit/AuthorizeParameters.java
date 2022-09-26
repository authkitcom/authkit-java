package com.authkit;

import java.security.SecureRandom;
import java.util.Base64;

public class AuthorizeParameters {

  private String clientId;
  private String codeChallenge;
  private String codeChallengeMethod;
  private String redirectUri;
  private String state;
  private String nonce;
  private String[] scope;

  private String prompt;

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }

  public void setCodeChallenge(String codeChallenge) {
    this.codeChallenge = codeChallenge;
  }

  public String getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public void setCodeChallengeMethod(String codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  public String[] getScope() {
    return scope;
  }

  public void setScope(String[] scope) {
    this.scope = scope;
  }

  public String getPrompt() {
    return prompt;
  }

  public void setPrompt(String prompt) {
    this.prompt = prompt;
  }

  /** Generates a nonce and stores in the nonce field */
  public void generateNonce() {

    SecureRandom secureRandom = new SecureRandom();
    byte[] value = new byte[32];
    secureRandom.nextBytes(value);
    nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  /**
   * Generates a PKCE challenge and verifier. Stores challenge and method.
   *
   * @return verifier value
   */
  public String generatePkce() {

    var pkce = new Pkce();

    codeChallenge = pkce.getChallenge();
    codeChallengeMethod = pkce.getMethod();

    return pkce.getVerifier();
  }
}
