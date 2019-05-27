package com.manning.apisecurityinaction.oauth2;

import java.util.Set;

public class AccessDecision {
    public final boolean granted;
    public final Set<String> scope;
    public final String resourceOwner;

    private AccessDecision(boolean granted, Set<String> scope,
                           String resourceOwner) {
        this.granted = granted;
        this.scope = scope;
        this.resourceOwner = resourceOwner;
    }

    public static AccessDecision allowed(String resourceOwner,
                                         Set<String> scope) {
        return new AccessDecision(true, scope, resourceOwner);
    }

    public static AccessDecision denied() {
        return new AccessDecision(false, null, null);
    }
}
