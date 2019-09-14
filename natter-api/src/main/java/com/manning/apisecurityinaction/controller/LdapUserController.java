package com.manning.apisecurityinaction.controller;

import javax.naming.*;
import javax.naming.directory.*;
import java.util.*;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.*;
import spark.*;

public class LdapUserController extends UserController {
    private static final Logger logger =
            LoggerFactory.getLogger(LdapUserController.class);

    private final String ldapUrl;
    private final String baseDn;
    private final DirContext connection;

    public LdapUserController(Database database, String ldapUrl,
                              String baseDn, String connDn,
                              String connPassword) throws NamingException {
        super(database);
        this.ldapUrl = ldapUrl;
        this.baseDn = baseDn;
        this.connection = bind(connDn, connPassword);
    }

    @Override
    public JSONObject registerUser(Request request, Response response) {
        throw new UnsupportedOperationException(
                "Please register users in LDAP directly");
    }

    @Override
    public void authenticate(Request request, Response response) {
        var credentials = getCredentials(request);
        if (credentials == null) return;

        var username = credentials[0];
        var password = credentials[1];

        var dn = "uid=" + username + ",ou=people," + baseDn;

        try {
            var directory = bind(dn, password);
            // Authentication succeeded
            request.attribute("subject", username);
            directory.close();

            // Lookup static groups for the user
            var searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[] { "cn" });

            var groups = new ArrayList<String>();
            var results = connection.search("ou=groups," + baseDn,
                    "(&(objectClass=groupOfNames)(member={0}))",
                    new Object[]{ dn },
                    searchControls);
            try {
                while (results.hasMore()) {
                    var result = results.next();
                    groups.add((String) result.getAttributes()
                            .get("cn").get(0));
                }
            } finally {
                results.close();
            }
            request.attribute("groups", groups);
        } catch (AuthenticationException e) {
            logger.debug("Authentication failed for user {}", username, e);
        } catch (NamingException e) {
            throw new RuntimeException("Unable to login", e);
        }
    }

    private DirContext bind(String userDn, String password)
            throws NamingException {
        var props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapUrl);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, userDn);
        props.put(Context.SECURITY_CREDENTIALS, password);

        return new InitialDirContext(props);
    }
}
