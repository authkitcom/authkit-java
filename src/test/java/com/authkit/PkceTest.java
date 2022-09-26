package com.authkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class PkceTest {

  @Test
  public void ctor() throws NoSuchAlgorithmException {

    var iterations = 10000;

    Set<String> challenges = new HashSet<String>();

    for (int i = 0; i < iterations; i++) {

      var unit = new Pkce();

      challenges.add(unit.getChallenge());
      assertThat(unit.getMethod()).isEqualTo("S256");

      // This is just a copy of the code in the constructor. May be a better way to externally
      // validate this
      byte[] bytes = unit.getVerifier().getBytes(StandardCharsets.US_ASCII);
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(bytes, 0, bytes.length);
      byte[] digest = messageDigest.digest();
      var reference = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

      assertThat(unit.getChallenge()).isEqualTo(reference);
    }

    assertThat(challenges).hasSize(iterations);
  }
}
