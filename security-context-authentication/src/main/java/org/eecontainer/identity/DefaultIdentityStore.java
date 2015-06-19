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
import javax.security.identity.credential.Credential.Support;
import javax.security.identity.model.Caller;
import javax.security.identity.model.Group;
import javax.security.identity.model.Role;
import java.security.PermissionCollection;
import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@ApplicationScoped
public class DefaultIdentityStore implements IdentityStore {

    private static final long serialVersionUID = 6165256084171037823L;

    private Map<Class<? extends Credential>, Support> supportedCredentials = new HashMap<>();
    private Map<String, Set<String>> callerRoleMapping = new HashMap<>();
    private Map<String, Caller> callers = new HashMap<>();

    public DefaultIdentityStore() {
        this.supportedCredentials.put(PasswordCredential.class, Support.SUPPORTED);

        String defaultCallername = "john";

        this.callers.put(defaultCallername, () -> defaultCallername);

        HashSet<String> roles = new HashSet<>();

        roles.add("Manager");
        roles.add("Sales");

        this.callerRoleMapping.put(defaultCallername, roles);
    }

    @Override
    public Support getCredentialSupport(Class<? extends Credential> credentialType) {
        Support credentialSupport = this.supportedCredentials.get(credentialType);

        if (credentialSupport == null) {
            return Support.UNSUPPORTED;
        }

        return credentialSupport;
    }

    @Override
    public <C extends Credential> C getCredential(Caller caller, Class<C> credentialType) {
        return getCredential(caller, null, credentialType);
    }

    @Override
    public Credential verifyCredential(Credential credential) {
        return getCredential(credential.getCaller(), credential, credential.getClass());
    }

    @Override
    public Caller getCaller(String callerName) {
        return this.callers.get(callerName);
    }

    @Override
    public List<Caller> getCallers(String regEx) {
        return new ArrayList<>(this.callers.values());
    }

    @Override
    public List<Role> getRoles(String regEx) {
        return this.callerRoleMapping.values().stream().flatMap(new Function<Set<String>, Stream<Role>>() {
            @Override
            public Stream<Role> apply(Set<String> strings) {
                List<Role> roles = new ArrayList<>();

                for (String roleName : strings) {
                    roles.add(() -> roleName);
                }

                return roles.stream();
            }
        }).collect(Collectors.toList());
    }

    @Override
    public List<Role> getRoles(Caller caller) {
        return this.callerRoleMapping.get(caller.getName()).stream().map(new Function<String, Role>() {
            @Override
            public Role apply(String roleName) {
                return () -> roleName;
            }
        }).collect(Collectors.toList());
    }

    @Override
    public boolean hasRole(String roleName, Caller caller) {
        Set<String> roles = this.callerRoleMapping.get(caller.getName());

        if (roles == null) {
            return false;
        }

        return roles.contains(roleName);
    }

    @Override
    public boolean hasRole(String groupName, Group group) {
        return false;
    }

    @Override
    public List<Group> getGroups(Caller principal) {
        return Collections.emptyList();
    }

    @Override
    public boolean isMember(Caller principal) {
        return false;
    }

    @Override
    public PermissionCollection getPermissions(Caller principal) {
        return Policy.UNSUPPORTED_EMPTY_COLLECTION;
    }

    private <C extends Credential> C getCredential(Caller caller, Credential credential, Class<C> credentialType) {
        if (PasswordCredential.class.isAssignableFrom(credentialType)) {
            C validCredential = (C) new PasswordCredential(caller, "passwd".toCharArray());

            if (credential != null) {
                if (credential.equals(validCredential)) {
                    return (C) new PasswordCredential(caller, "passwd".toCharArray(), Credential.Status.VALID);
                }
            }
        }

        return null;
    }
}
