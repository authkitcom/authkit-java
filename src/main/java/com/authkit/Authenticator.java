package com.authkit;

import reactor.core.publisher.Mono;

public interface Authenticator {

  Mono<AuthkitPrincipal> authenticate(String accessToken);
}
