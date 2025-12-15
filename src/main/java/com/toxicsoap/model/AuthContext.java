package com.toxicsoap.model;

public class AuthContext {

    private static final ThreadLocal<AuthContext> CONTEXT = new ThreadLocal<>();

    private String username;
    private String role;
    private boolean authenticated;

    public AuthContext() {
        this.authenticated = false;
    }

    public static AuthContext get() {
        AuthContext ctx = CONTEXT.get();
        if (ctx == null) {
            ctx = new AuthContext();
            CONTEXT.set(ctx);
        }
        return ctx;
    }

    public static void set(AuthContext context) {
        CONTEXT.set(context);
    }

    public static void clear() {
        CONTEXT.remove();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public boolean hasRole(String requiredRole) {
        if (!authenticated || role == null) {
            return false;
        }
        if ("ADMIN".equals(role)) {
            return true;
        }
        return role.equals(requiredRole);
    }
}
