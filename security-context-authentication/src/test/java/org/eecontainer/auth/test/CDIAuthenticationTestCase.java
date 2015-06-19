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
package org.eecontainer.auth.test;

import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.security.auth.SecurityContext;
import javax.security.identity.model.Caller;
import javax.servlet.ServletException;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.eecontainer.identity.credential.PasswordCredential;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@RunWith(WeldRunner.class)
public class CDIAuthenticationTestCase {

    @Inject
    private SecurityContext securityContext;

    @Test
    public void testAuthentication() {
        assertFalse(this.securityContext.isAuthenticated());

        this.securityContext.login(new PasswordCredential(createPrincipal(), "passwd".toCharArray()));

        assertTrue(this.securityContext.isAuthenticated());
        assertEquals(createPrincipal().getName(), this.securityContext.getCaller().getName());
        assertTrue(this.securityContext.isCallerInRole("Sales"));
    }

    @Test
    public void testLogout() throws ServletException {
        assertNull(this.securityContext.getCaller());

        this.securityContext.login(new PasswordCredential(createPrincipal(), "passwd".toCharArray()));

        assertEquals(createPrincipal().getName(), this.securityContext.getCaller().getName());

        this.securityContext.logout();

        assertNull(this.securityContext.getCaller());
        assertFalse(this.securityContext.isAuthenticated());
    }

    private Caller createPrincipal() {
        return () -> "john";
    }

}
