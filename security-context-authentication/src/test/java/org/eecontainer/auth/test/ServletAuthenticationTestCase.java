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

import org.eecontainer.servlet.DefaultHttpServletRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.security.auth.SecurityContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@RunWith(WeldRunner.class)
public class ServletAuthenticationTestCase {

    @Inject
    private SecurityContext securityContext;
    private HttpServletRequest servletRequest;

    @Before
    public void onBefore() {
        this.servletRequest = new DefaultHttpServletRequest(this.securityContext);
    }

    @Test
    public void testAuthentication() throws ServletException {
        assertNull(this.servletRequest.getUserPrincipal());

        this.servletRequest.login("john", "passwd");

        assertEquals(createPrincipal().getName(), this.servletRequest.getUserPrincipal().getName());
        assertTrue(this.servletRequest.isUserInRole("Manager"));
    }

    @Test
    public void testLogout() throws ServletException {
        assertNull(this.servletRequest.getUserPrincipal());

        this.servletRequest.login("john", "passwd");

        assertEquals(createPrincipal().getName(), this.servletRequest.getUserPrincipal().getName());

        this.servletRequest.logout();

        assertNull(this.servletRequest.getUserPrincipal());
    }

    private Principal createPrincipal() {
        return () -> "john";
    }

}
