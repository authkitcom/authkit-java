package com.authkit;

import com.authkit.Authenticator;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.authkit.Util.required;

public class DefaultAuthenticator implements Authenticator {

    private static final Gson GSON = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy
            .LOWER_CASE_WITH_UNDERSCORES).create();

    private static final Set<String> RESERVED_CLAIMS = new HashSet<String>();

    static {
        RESERVED_CLAIMS.add("email");
        RESERVED_CLAIMS.add("family_name");
        RESERVED_CLAIMS.add("given_name");
        RESERVED_CLAIMS.add("roles");
        RESERVED_CLAIMS.add("permissions");
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

    // Visible for testing
    OpenIdConfiguration openIdConfiguration;
    Jwks jwks;
    PublicKey publicKey;
    JwtParser jwtParser;

    public DefaultAuthenticator(Config config) {

        loadOpenIdConfig(config.getIssuer());
        loadCertificates();

        JwtParserBuilder builder = Jwts.parserBuilder().setSigningKey(publicKey)
                .requireIssuer(openIdConfiguration.issuer);

        if (config.getAudience() != null) {
            builder.requireAudience(config.getAudience());
        }

        jwtParser = builder.build();
    }

    private void loadOpenIdConfig(String issuer) {

        openIdConfiguration = loadObjectFromUrl(issuer + "/.well-known/openid-configuration",
                OpenIdConfiguration.class, null);
        jwks = loadObjectFromUrl(openIdConfiguration.jwksUri, Jwks.class, null);
    }

    private void loadCertificates() {

        try {

            String input = jwks.keys[0].x5c[0];
            byte[] inputBytes = Base64.getDecoder().decode(input);

            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream is = new ByteArrayInputStream (inputBytes);
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            publicKey = cer.getPublicKey();

        } catch (Exception e) {
            throw new AuthkitException(e);
        }
    }

    @Override
    public AuthkitPrincipal authenticate(String token) {

        Jws<Claims> jws = jwtParser.parseClaimsJws(token);

        Claims claims = jws.getBody();

        AuthkitPrincipal p = new AuthkitPrincipal();

        p.setSubject(claims.getSubject());
        p.setAudience(claims.getAudience());

        // TODO - This is called way too many times
        Map<String, ?> userinfo = loadObjectFromUrl(openIdConfiguration.userinfoEndpoint, Map.class, token);

        p.setEmail((String) userinfo.get("email"));
        p.setFamilyName((String) userinfo.get("family_name"));
        p.setGivenName((String) userinfo.get("given_name"));
        p.setIssuer(claims.getIssuer());
        p.setPermissions(stringArrayToStringSetClaim(claims, "permissions"));
        p.setRoles(stringArrayToStringSetClaim(claims, "roles"));
        p.setMetadata(new HashMap<String, Object>());

        for (Map.Entry<String, ?> e : userinfo.entrySet()) {
            if (! RESERVED_CLAIMS.contains(e.getKey())) {
                p.getMetadata().put(e.getKey(), e.getValue());
            }
        }

        return p;
    }

    private Set<String> stringArrayToStringSetClaim(Claims claims, String name) {

        Set<String> claim = new HashSet<String>();

        ArrayList<String> raw = claims.get(name, ArrayList.class);

        if (raw == null) {
            return null;
        }

        for (String c : raw) {
            claim.add(c);
        }

        return claim;
    }

    private <T> T loadObjectFromUrl(String url, Class<T> objectType, String token)  {

        try {

            URL _url = new URL(url);
            HttpURLConnection con = (HttpURLConnection) _url.openConnection();
            con.setRequestMethod("GET");
            if (token != null) {
                con.setRequestProperty("Authorization", "Bearer " + token);
            }
            con.connect();

            int status = con.getResponseCode();

            switch (status) {
                case 200:
                case 201:
                    BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line+"\n");
                    }

                    br.close();

                    return GSON.fromJson(sb.toString(), objectType);
                default:
                    throw new AuthkitException("Invalid status code: " + status);
            }

        } catch (Exception e) {
            throw new AuthkitException(e);
        }
    }
}