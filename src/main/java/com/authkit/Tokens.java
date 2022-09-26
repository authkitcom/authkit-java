package com.authkit;

/** Tokens returned from the authorize flow */
public class Tokens {

  private final String accessToken;
  private final String idToken;
  private final String refreshToken;
  private final int expiresIn;

  public Tokens(String accessToken, String idToken, String refreshToken, int expiresIn) {
    this.accessToken = accessToken;
    this.idToken = idToken;
    this.refreshToken = refreshToken;
    this.expiresIn = expiresIn;
  }

  public String getAccessToken() {
    return accessToken;
  }

  public String getIdToken() {
    return idToken;
  }

  public String getRefreshToken() {
    return refreshToken;
  }

  public int getExpiresIn() {
    return expiresIn;
  }
}
