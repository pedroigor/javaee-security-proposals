/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
//
// This source code implements specifications defined by the Java
// Community Process. In order to remain compliant with the specification
// DO NOT add / change / or delete method signatures!
//
package javax.security.identity;

import javax.security.identity.credential.Credential;
import javax.security.identity.credential.Credential.Support;
import javax.security.identity.model.Caller;
import javax.security.identity.model.Group;
import javax.security.identity.model.Role;
import java.io.Serializable;
import java.security.PermissionCollection;
import java.util.List;

public interface IdentityStore extends Serializable {

    // credential management
    Support getCredentialSupport(Class<? extends Credential> credentialType);

    <C extends Credential> C getCredential(Caller caller, Class<C> credentialType);

    Credential verifyCredential(Credential credential);

    // caller management
    Caller getCaller(String callerName);
    List<Caller> getCallers(String regEx);

    // role management
    List<Role> getRoles(String regEx);

    // role mapping
    List<Role> getRoles(Caller caller);
    boolean hasRole(String roleName, Caller caller);
    boolean hasRole(String roleName, Group group);

    // group management
    List<Group> getGroups(Caller principal);

    // group mapping
    boolean isMember(Caller principal);

    // permission mapping
    PermissionCollection getPermissions(Caller principal);
}