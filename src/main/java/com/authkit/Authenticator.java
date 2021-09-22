package com.authkit;

import org.reactivestreams.Publisher;

public interface Authenticator {

    Publisher<AuthkitPrincipal> authenticate(String token);
}
