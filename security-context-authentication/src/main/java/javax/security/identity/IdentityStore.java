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
import javax.security.identity.credential.CredentialSupport;
import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

public interface IdentityStore extends Serializable {

    CredentialSupport getCredentialSupport(Class<? extends Credential> credentialType);

    <C extends Credential> C getCredential(Principal principal, Class<C> credentialType);

    Principal verifyCredential(Credential credential);

    Set<String> getRoles(Principal principal);
}
