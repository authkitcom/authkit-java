package com.authkit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;
import org.reactivestreams.Publisher;
import reactor.cache.CacheMono;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;
import reactor.netty.http.client.HttpClient;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;

public class DefaultAuthenticator implements Authenticator {

    /*
    TODO - unit test missing audience / mismatch audience
    TODO - test failure to retrieve data
     */
    private static final Gson GSON = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy
            .LOWER_CASE_WITH_UNDERSCORES).create();

    private static final Set<String> RESERVED_CLAIMS = new HashSet<String>();

    // TODO - Enum would be better here
    private static final String CLAIM_SUB = "sub";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_EMAIL_VERIFIED = "email_verified";
    private static final String CLAIM_FAMILY_NAME = "family_name";
    private static final String CLAIM_GENDER = "gender";
    private static final String CLAIM_GIVEN_NAME = "given_name";
    private static final String CLAIM_GROUPS = "groups";
    private static final String CLAIM_MIDDLE_NAME = "middle_name";
    private static final String CLAIM_NAME = "name";
    private static final String CLAIM_NICKNAME = "nickname";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_PHONE_NUMBER ="phone_number";
    private static final String CLAIM_PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_UPDATED_AT = "updated_at";
    private static final String CLAIM_METADATA = "metadata";

    static {

        RESERVED_CLAIMS.add(CLAIM_SUB);
        RESERVED_CLAIMS.add(CLAIM_EMAIL);
        RESERVED_CLAIMS.add(CLAIM_EMAIL_VERIFIED);
        RESERVED_CLAIMS.add(CLAIM_FAMILY_NAME);
        RESERVED_CLAIMS.add(CLAIM_GENDER);
        RESERVED_CLAIMS.add(CLAIM_GIVEN_NAME);
        RESERVED_CLAIMS.add(CLAIM_GROUPS);
        RESERVED_CLAIMS.add(CLAIM_MIDDLE_NAME);
        RESERVED_CLAIMS.add(CLAIM_NAME);
        RESERVED_CLAIMS.add(CLAIM_NICKNAME);
        RESERVED_CLAIMS.add(CLAIM_PERMISSIONS);
        RESERVED_CLAIMS.add(CLAIM_PHONE_NUMBER);
        RESERVED_CLAIMS.add(CLAIM_PHONE_NUMBER_VERIFIED);
        RESERVED_CLAIMS.add(CLAIM_PREFERRED_USERNAME);
        RESERVED_CLAIMS.add(CLAIM_ROLES);
        RESERVED_CLAIMS.add(CLAIM_UPDATED_AT);
        RESERVED_CLAIMS.add(CLAIM_METADATA);
    }

    private static class MinimalHeader {
        private String kid;
    }

    private static class MinimalBody {
        private String iss;
        private String aud;
    }

    public static class OpenIdConfiguration {
        private String authorizationEndpoint;
        private String[] grantTypesSupported;
        private String[] idTokenSigningAlgValuesSupported;
        private String issuer;
        private String jwksUri;
        private String[] responseModesSupported;
        private String[] responseTypesSupported;
        private String revocationEndpoint;
        private String[] subjectTypesSupported;
        private String tokenEndpoint;
        private String userinfoEndpoint;
    }

    public static class Jwks {
        private Key[] keys;
    }

    public static class Key {
        private String alg;
        private String e;
        private String kid;
        private String kty;
        private String n;
        private String use;
        private String[] x5c;
        private String x5t;
    }

    private static class ParserAndUserinfoEndpoint {

        private final JwtParser parser;
        private final String userinfoEndpoint;

        private ParserAndUserinfoEndpoint(JwtParser parser, String userinfoEndpoint) {
            this.parser = parser;
            this.userinfoEndpoint = userinfoEndpoint;
        }
    }

    private static class Tuple<T1, T2> {
        private final T1 value1;
        private final T2 value2;

        private Tuple(T1 value1, T2 value2) {
            this.value1 = value1;
            this.value2 = value2;
        }
    }

    private final String issuer;
    private final String audience;
    private final HttpClient client;

    private final Cache<String, AuthkitPrincipal> principalCache = Caffeine.newBuilder()
        .maximumSize(10_000)
        .expireAfterWrite(Duration.ofMinutes(120))
        .build();

    private final Cache<String, ParserAndUserinfoEndpoint> keyIdAndUserinfoCache = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(Duration.ofMinutes(120))
        .build();

    public DefaultAuthenticator(Config config) {

        // TODO - Test with and without audience
        this.issuer = config.getIssuer();
        this.audience = config.getAudience();
        this.client = HttpClient.create();
    }

    /**
     return Mono.from(getParserAndUserinfo())*
     * @param keyId keyId to extract
     * @return
     */
    private Mono<ParserAndUserinfoEndpoint> getParserAndUserinfo(String keyId) {
        return CacheMono.lookup(k -> Mono.justOrEmpty(keyIdAndUserinfoCache.getIfPresent(k)).map(Signal::next),
                keyId)
            .onCacheMissResume(Mono.from(doGetParserAndUserinfo(keyId)))
            .andWriteWith((k, u) -> Mono.fromRunnable(() -> {
                if (u.hasValue()) {
                    keyIdAndUserinfoCache.put(k, u.get());
                }
            }));
    }

    private Mono<ParserAndUserinfoEndpoint> doGetParserAndUserinfo(String keyId) {
        return client.get().uri(issuer + "/.well-known/openid-configuration").responseSingle((r, b) -> {
                if (r.status().code() == 200) {
                    return b.asInputStream();
                } else {
                    // TODO - Want some better logging here
                    throw new AuthkitException("unable to load openid-configuration, code: " + r.status().code());
                }
            }).map(i -> GSON.fromJson(new InputStreamReader(i), OpenIdConfiguration.class))
            .flatMap(oidc -> client.get().uri(oidc.jwksUri).responseSingle((r, b) -> {
                if (r.status().code() == 200) {
                    return b.asInputStream().map(i -> new Tuple<>(i, oidc.userinfoEndpoint));
                } else {
                    // TODO - Want some better logging here
                    throw new AuthkitException("unable to load jwks, code: " + r.status().code());
                }
            }).map(i -> new Tuple<>(GSON.fromJson(new InputStreamReader(i.value1), Jwks.class), i.value2)))
            .map(j -> {
                try {
                    String input = j.value1.keys[0].x5c[0];
                    byte[] inputBytes = Base64.getDecoder().decode(input);
                    var fact = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream is = new ByteArrayInputStream (inputBytes);
                    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                    return new Tuple<>(cer.getPublicKey(), j.value2);
                } catch (Exception e) {
                    throw new AuthkitException(e);
                }
            }).map(pk -> {

                JwtParserBuilder builder = Jwts.parserBuilder().setSigningKey(pk.value1)
                    .requireIssuer(issuer);

                return new ParserAndUserinfoEndpoint(builder.build(), pk.value2);
            });
    };

    @Override
    public Publisher<AuthkitPrincipal> authenticate(final String token) {
        return CacheMono.lookup(k -> Mono.justOrEmpty(principalCache.getIfPresent(k)).map(Signal::next),
            token)
            .onCacheMissResume(Mono.from(doAuthenticate(token)))
            .andWriteWith((k, u) -> Mono.fromRunnable(() -> {
                if (u.hasValue()) {
                    principalCache.put(k, u.get());
                }
            }));
    }

    private String validateAndGetKeyId(String token) {
        var parts = token.split("\\.", 3);
        // TODO - Check segments
        if (parts.length != 3) {
            throw new AuthkitException("invalid jwt");
        }
        var headerString = new String(Base64.getDecoder().decode(parts[0]));
        var header = GSON.fromJson(headerString, MinimalHeader.class);
        var bodyString = new String(Base64.getDecoder().decode(parts[1]));
        var body = GSON.fromJson(bodyString, MinimalBody.class);

        if (! issuer.equals(body.iss)) {
            throw new AuthkitException("invalid issuer");
        }
        // TODO - Test this
        if (audience != null && (! audience.equals(body.aud))) {
            throw new AuthkitException("invalid audience");
        }
        if (header.kid == null) {
            throw new AuthkitException("header missing kid");
        }
        return header.kid;
    }


    public Publisher<AuthkitPrincipal> doAuthenticate(final String token) {

        return Mono.fromCallable(() -> validateAndGetKeyId(token))
            .flatMap(this::getParserAndUserinfo).map(j -> {

            var jws = j.parser.parseClaimsJws(token);
            var claims = jws.getBody();

            AuthkitPrincipal p = new AuthkitPrincipal();

            p.setIssuer(claims.getIssuer());
            p.setSub(claims.getSubject());
            p.setAudience(claims.getAudience());
            // We assume claims are in access token
            p.setPermissions(orDefaultSet(claims.get(CLAIM_PERMISSIONS)));
            p.setRoles(orDefaultSet(claims.get(CLAIM_ROLES)));
            p.setGroups(orDefaultSet(claims.get(CLAIM_GROUPS)));

            // TODO - Set other values from the access token here

            return new Tuple<>(p, j.userinfoEndpoint);
        }).flatMap(t -> client.headers(h -> h.add("Authorization", "Bearer " + token)).get().uri(t.value2).responseSingle((r, b) -> {
            if (r.status().code() == 200) {
                return b.asInputStream().map(i -> new Tuple<>(i, t.value1));
            } else {
                // TODO - Want some better logging here
                throw new AuthkitException("unable to load userinfo, code: " + r.status().code());
            }
        })).map(t -> {

            var userinfo = GSON.fromJson(new InputStreamReader(t.value1), HashMap.class);
            var p = t.value2;

            p.setEmail((String) userinfo.get(CLAIM_EMAIL));
            p.setEmailVerified((Boolean) userinfo.get(CLAIM_EMAIL_VERIFIED));
            p.setFamilyName((String) userinfo.get(CLAIM_FAMILY_NAME));
            p.setGender((String) userinfo.get(CLAIM_GENDER));
            p.setGivenName((String) userinfo.get(CLAIM_GIVEN_NAME));
            p.setMiddleName((String) userinfo.get(CLAIM_MIDDLE_NAME));
            p.setClaimName((String) userinfo.get(CLAIM_NAME));
            p.setNickname((String) userinfo.get(CLAIM_NICKNAME));
            p.setPhoneNumber((String) userinfo.get(CLAIM_PHONE_NUMBER));
            p.setPhoneNumberVerified((Boolean) userinfo.get(CLAIM_PHONE_NUMBER_VERIFIED));
            p.setPreferredUsername((String) userinfo.get(CLAIM_PREFERRED_USERNAME));
            p.setUpdatedAt(toLong((Double) userinfo.get(CLAIM_UPDATED_AT)));
            p.setMetadata(orDefaultMap(userinfo.get(CLAIM_METADATA)));

            if (p.getPermissions().isEmpty()) {
                p.setPermissions(orDefaultSet(userinfo.get(CLAIM_PERMISSIONS)));
            }
            if (p.getGroups().isEmpty()) {
                p.setGroups(orDefaultSet(userinfo.get(CLAIM_GROUPS)));
            }
            if (p.getRoles().isEmpty()) {
                p.setRoles(orDefaultSet(userinfo.get(CLAIM_ROLES)));
            }

            userinfo.forEach((k, v) -> {
                var key = (String) k;
                if (! RESERVED_CLAIMS.contains(k)) {
                    p.getExtraClaims().put(key, v);
                }
            });

            return p;

        });

    }

    private static Long toLong(Double input) {

        if (input == null) {
            return null;
        } else {
            return input.longValue();
        }

    }

    private static Set<String> stringArrayToStringSetClaim(Claims claims, String name) {

        ArrayList<String> raw = claims.get(name, ArrayList.class);

        if (raw == null) {
            return new HashSet<>();
        }

        return new HashSet<>(raw);
    }

    private static Set<String> orDefaultSet(Object input) {

        if (input != null) {
            var result = new HashSet<String>();
            for (var el :((List<String>) input)) {
                result.add(el);
            }
            return result;
        } else {
            return Set.of();
        }
    }

    private Map<String, Object> orDefaultMap(Object input) {

        if (input != null) {
            return (Map<String, Object>) input;
        } else {
            return Map.of();
        }
    }
}