/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.dao;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link FIDO2DeviceStoreDAO#getStoredUsernameIgnoreCase} (issue #7113).
 *
 * <p>The FIDO2 test module has no H2 / data-source harness, so following the established Mockito-inline
 * DAO-testing style in this module these tests drive a mocked JDBC connection and assert: the
 * case-insensitive SQL is issued, the three parameters (tenant id, domain, request username) are bound
 * verbatim, and the row/no-row return contract. The case-insensitive matching itself is delegated to SQL
 * {@code LOWER(USER_NAME) = LOWER(?)}, which is asserted by pinning the exact query constant.</p>
 */
public class FIDO2DeviceStoreDAOTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String DOMAIN_NAME = "PRIMARY";
    private static final String STORED_USERNAME = "johndoe";

    private FIDO2DeviceStoreDAO dao;

    @Mock
    private Connection connection;
    @Mock
    private PreparedStatement preparedStatement;
    @Mock
    private ResultSet resultSet;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMock;

    @BeforeMethod
    public void setUp() throws Exception {

        dao = new FIDO2DeviceStoreDAO();
        MockitoAnnotations.openMocks(this);

        identityDatabaseUtilMock = mockStatic(IdentityDatabaseUtil.class);
        identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);

        identityDatabaseUtilMock.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                .GET_USERNAME_BY_CASE_INSENSITIVE_USERNAME)).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
    }

    @AfterMethod
    public void tearDown() {

        if (identityDatabaseUtilMock != null) {
            identityDatabaseUtilMock.close();
        }
        if (identityTenantUtilMock != null) {
            identityTenantUtilMock.close();
        }
    }

    private User user(String username) {

        User user = new User();
        user.setUserName(username);
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserStoreDomain(DOMAIN_NAME);
        return user;
    }

    @Test(description = "Enrolled 'johndoe': a differing-case lookup ('Johndoe') resolves to the stored 'johndoe' " +
            "and binds tenant id, domain and the request username to the case-insensitive query.")
    public void testReturnsStoredUsernameForCaseDifferingLookup() throws Exception {

        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(FIDO2AuthenticatorConstants.USERNAME)).thenReturn(STORED_USERNAME);

        String resolved = dao.getStoredUsernameIgnoreCase(user("Johndoe"));

        Assert.assertEquals(resolved, STORED_USERNAME,
                "Case-insensitive lookup must return the stored (enrolled) username case.");
        verify(connection).prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                .GET_USERNAME_BY_CASE_INSENSITIVE_USERNAME);
        verify(preparedStatement).setInt(1, TENANT_ID);
        verify(preparedStatement).setString(2, DOMAIN_NAME);
        verify(preparedStatement).setString(3, "Johndoe");
    }

    @Test(description = "Enrolled 'johndoe': an all-caps lookup ('JOHNDOE') resolves to the stored 'johndoe'.")
    public void testReturnsStoredUsernameForUpperCaseLookup() throws Exception {

        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(FIDO2AuthenticatorConstants.USERNAME)).thenReturn(STORED_USERNAME);

        String resolved = dao.getStoredUsernameIgnoreCase(user("JOHNDOE"));

        Assert.assertEquals(resolved, STORED_USERNAME);
        verify(preparedStatement).setString(3, "JOHNDOE");
    }

    @Test(description = "Exact-case lookup ('johndoe') returns the stored 'johndoe'.")
    public void testReturnsStoredUsernameForExactLookup() throws Exception {

        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(FIDO2AuthenticatorConstants.USERNAME)).thenReturn(STORED_USERNAME);

        String resolved = dao.getStoredUsernameIgnoreCase(user("johndoe"));

        Assert.assertEquals(resolved, STORED_USERNAME);
    }

    @Test(description = "A user with NO registered passkey (no matching row) returns null.")
    public void testReturnsNullWhenNoPasskeyRegistered() throws Exception {

        when(resultSet.next()).thenReturn(false);

        String resolved = dao.getStoredUsernameIgnoreCase(user("Nobody"));

        Assert.assertNull(resolved, "A user with no enrolled passkey must resolve to null.");
    }

    @Test(description = "Domain isolation: the lookup binds the requested DOMAIN_NAME, so a row stored under a " +
            "different domain (filtered out by SQL, no row returned) yields null.")
    public void testDomainIsolationReturnsNull() throws Exception {

        // Row exists under DOMAIN 'X' but the query is scoped to 'PRIMARY' (DOMAIN_NAME = ?) so no row matches.
        when(resultSet.next()).thenReturn(false);

        String resolved = dao.getStoredUsernameIgnoreCase(user("johndoe"));

        Assert.assertNull(resolved);
        verify(preparedStatement).setString(2, DOMAIN_NAME);
    }

    @Test(description = "A SQLException from the query is wrapped in a FIDO2AuthenticatorServerException.",
            expectedExceptions = {FIDO2AuthenticatorServerException.class})
    public void testWrapsSqlException() throws Exception {

        when(preparedStatement.executeQuery()).thenThrow(new SQLException("boom"));

        dao.getStoredUsernameIgnoreCase(user("johndoe"));
    }

    @Test(description = "Connections are always closed via IdentityDatabaseUtil.closeAllConnections.")
    public void testClosesConnections() throws Exception {

        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(FIDO2AuthenticatorConstants.USERNAME)).thenReturn(STORED_USERNAME);

        dao.getStoredUsernameIgnoreCase(user("johndoe"));

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.closeAllConnections(
                eq(connection), any(ResultSet.class), any(PreparedStatement.class)));
    }
}
