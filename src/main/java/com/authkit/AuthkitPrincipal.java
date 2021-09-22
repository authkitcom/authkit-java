package com.authkit;

import java.security.Principal;
import java.util.*;

public class AuthkitPrincipal implements Principal {

    private String issuer;
    private String sub;
    private String audience;

    private String email;
    private Boolean emailVerified;
    private String familyName;
    private String gender;
    private String givenName;
    private Set<String> groups = new HashSet<>();
    private String middleName;
    private String name;
    private String nickname;
    private Set<String> permissions = new HashSet<>();
    private String phoneNumber;
    private Boolean phoneNumberVerified;
    private String preferredUsername;
    private Set<String> roles = new HashSet<>();
    private Long updatedAt;
    private Map<String, Object> metadata = new HashMap<String, Object>();
    private Map<String, Object> extraClaims = new HashMap<String, Object>();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public Set<String> getGroups() {
        return groups;
    }

    public void setGroups(Set<String> groups) {
        this.groups = groups;
    }

    public String getMiddleName() {
        return middleName;
    }

    public void setMiddleName(String middleName) {
        this.middleName = middleName;
    }

    @Override
    public String getName() {
        return preferredUsername;
    }

    public String getClaimName() {
        return name;
    }

    public void setClaimName(String name) {
        this.name = name;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public Boolean getPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public void setPhoneNumberVerified(Boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
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

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public Map<String, Object> getExtraClaims() {
        return extraClaims;
    }

    public void setExtraClaims(Map<String, Object> extraClaims) {
        this.extraClaims = extraClaims;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthkitPrincipal that = (AuthkitPrincipal) o;
        return Objects.equals(issuer, that.issuer) && Objects.equals(sub, that.sub) && Objects.equals(audience, that.audience) && Objects.equals(email, that.email) && Objects.equals(emailVerified, that.emailVerified) && Objects.equals(familyName, that.familyName) && Objects.equals(gender, that.gender) && Objects.equals(givenName, that.givenName) && Objects.equals(groups, that.groups) && Objects.equals(middleName, that.middleName) && Objects.equals(name, that.name) && Objects.equals(nickname, that.nickname) && Objects.equals(permissions, that.permissions) && Objects.equals(phoneNumber, that.phoneNumber) && Objects.equals(phoneNumberVerified, that.phoneNumberVerified) && Objects.equals(preferredUsername, that.preferredUsername) && Objects.equals(roles, that.roles) && Objects.equals(updatedAt, that.updatedAt) && Objects.equals(metadata, that.metadata) && Objects.equals(extraClaims, that.extraClaims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, sub, audience, email, emailVerified, familyName, gender, givenName, groups, middleName, name, nickname, permissions, phoneNumber, phoneNumberVerified, preferredUsername, roles, updatedAt, metadata, extraClaims);
    }

    @Override
    public String toString() {
        return "AuthkitPrincipal{" +
            "issuer='" + issuer + '\'' +
            ", subject='" + sub + '\'' +
            ", audience='" + audience + '\'' +
            ", email='" + email + '\'' +
            ", emailVerified=" + emailVerified +
            ", familyName='" + familyName + '\'' +
            ", gender='" + gender + '\'' +
            ", givenName='" + givenName + '\'' +
            ", groups=" + groups +
            ", middleName='" + middleName + '\'' +
            ", name='" + name + '\'' +
            ", nickname='" + nickname + '\'' +
            ", permissions=" + permissions +
            ", phoneNumber='" + phoneNumber + '\'' +
            ", phoneNumberVerified=" + phoneNumberVerified +
            ", preferredUsername='" + preferredUsername + '\'' +
            ", roles=" + roles +
            ", updatedAt=" + updatedAt +
            ", metadata=" + metadata +
            ", extraClaims=" + extraClaims +
            '}';
    }
}