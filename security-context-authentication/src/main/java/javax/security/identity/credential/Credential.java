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
package javax.security.identity.credential;

import javax.security.identity.model.Caller;
import java.security.Principal;

public interface Credential {

    Caller getCaller();

    Status getStatus();

    enum Status {
        /**
         * Indicates that the credential could not be validated, for example, if
         * no suitable <code>CredentialHandler</code>} could be found.
         */
        NOT_VALIDATED,

        /**
         * Indicates that the credential is not valid after a validation attempt.
         */
        INVALID,

        /**
         * Indicates that the credential is valid after a validation attempt.
         */
        VALID,

        /**
         * Indicates that the credential has expired.
         */
        EXPIRED,

        /**
         * Indicates that the {@link javax.security.idm.model.Caller} whose credentials were validated is disabled.
         */
        CALLER_DISABLED
    };

    enum Support {

        /**
         * The given credential type is unsupported for both obtaining the credential and verifying the credential.
         */
        UNSUPPORTED,

        /**
         * The given credential type is both obtainable and verifiable.
         */
        SUPPORTED
    }
}
