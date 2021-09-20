package com.authkit;

import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class AuthkitPrincipal implements Principal {

    private String issuer;
    private String subject;
    private String audience;
    private String givenName;
    private String familyName;
    private String email;
    private String preferredUsername;
    private Set<String> roles;
    private Set<String> permissions;
    private Map<String, Object> metadata;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    @Override
    public String getName() {
        return preferredUsername;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthkitPrincipal principal = (AuthkitPrincipal) o;
        return Objects.equals(issuer, principal.issuer) &&
                Objects.equals(subject, principal.subject) &&
                Objects.equals(audience, principal.audience) &&
                Objects.equals(givenName, principal.givenName) &&
                Objects.equals(familyName, principal.familyName) &&
                Objects.equals(email, principal.email) &&
                Objects.equals(preferredUsername, principal.preferredUsername) &&
                Objects.equals(roles, principal.roles) &&
                Objects.equals(permissions, principal.permissions) &&
                Objects.equals(metadata, principal.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, audience, givenName, familyName, email, preferredUsername, roles, permissions, metadata);
    }
}