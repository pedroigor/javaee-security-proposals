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
import javax.security.identity.IdentityStore;
import javax.security.identity.credential.Credential;
import javax.security.identity.credential.Credential.Support;
import javax.security.identity.model.Caller;
import javax.security.identity.model.Role;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@SessionScoped
public class DefaultSecurityContext implements SecurityContext {

    private static final long serialVersionUID = -5054373464615019115L;

    @Inject
    private IdentityStore identityStore;
    private Caller caller;

    @Override
    public Caller getCaller() {
        return this.caller;
    }

    @Override
    public boolean isCallerInRole(String roleName) {
        return this.identityStore.hasRole(roleName, getCaller());
    }

    @Override
    public List<Role> getRoles() {
        if (!isAuthenticated()) {
            return Collections.emptyList();
        }

        return this.identityStore.getRoles(this.caller);
    }

    @Override
    public boolean isAuthenticated() {
        return this.caller != null;
    }

    @Override
    public void login(Credential credential) {
        Support support = this.identityStore.getCredentialSupport(credential.getClass());

        if (Support.SUPPORTED.equals(support)) {
            Credential validatedCredential = this.identityStore.verifyCredential(credential);

            if (Credential.Status.VALID.equals(validatedCredential.getStatus())) {
                this.caller = this.identityStore.getCaller(credential.getCaller().getName());
            }
        }
    }

    @Override
    public void logout() {
        this.caller = null;
    }

    @Override
    public void runAs(String role, Function<?, ?> function) {
    }
}
