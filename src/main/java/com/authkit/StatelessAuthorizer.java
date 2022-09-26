package com.authkit;

import reactor.core.publisher.Mono;

/** Supports authorization flow without storage or server side bindings */
public interface StatelessAuthorizer {

  Mono<String> buildAuthorizeUrl(AuthorizeParameters params);

  Mono<Tokens> fetchTokens(FetchTokensParameters params);
}
