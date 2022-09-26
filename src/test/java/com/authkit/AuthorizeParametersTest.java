package com.authkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class AuthorizeParametersTest {

  @Test
  public void generateNonce() {

    var iterations = 100000;

    Set<String> nonces = new HashSet<>();

    for (int i = 0; i < iterations; i++) {

      var unit = new AuthorizeParameters();

      assertThat(unit.getNonce()).isNull();

      unit.generateNonce();

      assertThat(unit.getNonce()).isNotEmpty();
      assertThat(Base64.getUrlDecoder().decode(unit.getNonce())).hasSize(32);

      nonces.add(unit.getNonce());
    }

    assertThat(nonces).hasSize(iterations);
  }

  @Test
  public void generatePkce() {

    var unit = new AuthorizeParameters();

    assertThat(unit.getCodeChallenge()).isNull();
    assertThat(unit.getCodeChallengeMethod()).isNull();

    var verifier = unit.generatePkce();

    assertThat(unit.getCodeChallenge()).isNotEmpty();
    assertThat(unit.getCodeChallengeMethod()).isEqualTo("S256");
    assertThat(verifier).isNotEmpty();
  }
}
