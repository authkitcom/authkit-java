package com.authkit;

import com.authkit.AuthkitPrincipal;

public interface Authenticator {

    AuthkitPrincipal authenticate(String token);
}
