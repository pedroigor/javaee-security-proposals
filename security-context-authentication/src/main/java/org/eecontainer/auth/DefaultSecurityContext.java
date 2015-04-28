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
package org.eecontainer.auth;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.security.auth.SecurityContext;
import javax.security.identity.credential.Credential;
import javax.security.identity.credential.CredentialSupport;
import javax.security.identity.IdentityStore;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.function.Function;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@SessionScoped
public class DefaultSecurityContext implements SecurityContext {

    private static final long serialVersionUID = -5054373464615019115L;

    @Inject
    private IdentityStore identityStore;
    private Principal principal;

    @Override
    public Principal getUserPrincipal() {
        return this.principal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return getRoles().contains(role);
    }

    @Override
    public Set<String> getRoles() {
        if (!isAuthenticated()) {
            return Collections.emptySet();
        }

        return this.identityStore.getRoles(this.principal);
    }

    @Override
    public boolean isAuthenticated() {
        return this.principal != null;
    }

    @Override
    public void login(Credential credential) {
        CredentialSupport credentialSupport = this.identityStore.getCredentialSupport(credential.getClass());

        if (credentialSupport.isDefinitelyVerifiable()) {
            Principal principal = this.identityStore.verifyCredential(credential);

            if (principal != null) {
                this.principal = principal;
            }
        }
    }

    @Override
    public void logout() {
        this.principal = null;
    }

    @Override
    public void runAs(String role, Function<?, ?> function) {
    }
}
