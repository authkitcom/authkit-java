package com.authkit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class Pkce {

  private final String challenge;
  private final String verifier;
  private final String method = "S256";

  public Pkce() {

    try {
      SecureRandom secureRandom = new SecureRandom();
      byte[] codeVerifier = new byte[32];
      secureRandom.nextBytes(codeVerifier);
      verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);

      byte[] bytes = verifier.getBytes(StandardCharsets.US_ASCII);
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(bytes, 0, bytes.length);
      byte[] digest = messageDigest.digest();
      challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

    } catch (Exception e) {
      throw new AuthkitException(e);
    }
  }

  public String getChallenge() {
    return challenge;
  }

  public String getVerifier() {
    return verifier;
  }

  public String getMethod() {
    return method;
  }
}
