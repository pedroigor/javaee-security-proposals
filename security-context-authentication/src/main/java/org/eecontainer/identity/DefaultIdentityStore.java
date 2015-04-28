/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eecontainer.identity;

import org.eecontainer.identity.credential.PasswordCredential;

import javax.enterprise.context.ApplicationScoped;
import javax.security.identity.IdentityStore;
import javax.security.identity.credential.Credential;
import javax.security.identity.credential.CredentialSupport;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@ApplicationScoped
public class DefaultIdentityStore implements IdentityStore {

    private static final long serialVersionUID = 6165256084171037823L;

    private Map<Class<? extends Credential>, CredentialSupport> supportedCredentials = new HashMap<>();
    private Map<String, Set<String>> principalRoleMapping = new HashMap<>();

    public DefaultIdentityStore() {
        this.supportedCredentials.put(PasswordCredential.class, CredentialSupport.FULLY_SUPPORTED);

        HashSet<String> roles = new HashSet<>();

        roles.add("Manager");
        roles.add("Sales");

        this.principalRoleMapping.put("john", roles);
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<? extends Credential> credentialType) {
        CredentialSupport credentialSupport = this.supportedCredentials.get(credentialType);

        if (credentialSupport == null) {
            return CredentialSupport.UNKNOWN;
        }

        return credentialSupport;
    }

    @Override
    public <C extends Credential> C getCredential(Principal principal, Class<C> credentialType) {
        if (PasswordCredential.class.isAssignableFrom(credentialType)) {
            return (C) new PasswordCredential(principal, "passwd".toCharArray());
        }

        return null;
    }

    @Override
    public Principal verifyCredential(Credential credential) {
        Credential validCredential = getCredential(credential.getPrincipal(), credential.getClass());

        if (validCredential != null) {
            if (validCredential.equals(credential)) {
                return credential.getPrincipal();
            }
        }

        return null;
    }

    @Override
    public Set<String> getRoles(Principal principal) {
        Set<String> roles = this.principalRoleMapping.get(principal.getName());

        if (roles == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableSet(roles);
    }
}
