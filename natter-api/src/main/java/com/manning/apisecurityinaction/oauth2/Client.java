package com.manning.apisecurityinaction.oauth2;

import java.util.Set;

public class Client {
    public final String clientId;
    public final String displayName;
    public final Set<String> allowedScope;
    public final String defaultScope;

    public Client(String clientId, String displayName,
                  Set<String> allowedScope, String defaultScope) {
        this.clientId = clientId;
        this.displayName = displayName;
        this.allowedScope = allowedScope;
        this.defaultScope = defaultScope;
    }
}
