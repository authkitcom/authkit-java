package com.authkit;

public class FetchTokensParameters {

  private String code;
  private String redirectUri;
  private String codeVerifier;

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getCodeVerifier() {
    return codeVerifier;
  }

  public void setCodeVerifier(String codeVerifier) {
    this.codeVerifier = codeVerifier;
  }
}
