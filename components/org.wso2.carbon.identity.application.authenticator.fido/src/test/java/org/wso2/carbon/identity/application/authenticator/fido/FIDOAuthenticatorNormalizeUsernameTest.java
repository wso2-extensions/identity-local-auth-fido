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

package org.wso2.carbon.identity.application.authenticator.fido;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link FIDOAuthenticator#normalizeAuthenticatedUser} passkey-username-case normalization
 * (issue #7113). Exercises the case-sensitivity guard, the no-passkey (blank resolver result) path
 * and the resolver server-error path.
 */
public class FIDOAuthenticatorNormalizeUsernameTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String REQUEST_USERNAME = "Johndoe";   // case as supplied via authorize param.
    private static final String STORED_USERNAME = "johndoe";    // case the passkey was enrolled under.

    private FIDOAuthenticator fidoAuthenticator;

    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private UserRealm userRealm;
    @Mock
    private AbstractUserStoreManager userStoreManager;

    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<FIDOUtil> fidoUtilMock;
    private MockedStatic<FIDOAuthenticatorServiceComponent> fidoAuthenticatorServiceComponentMock;

    @BeforeMethod
    public void setUp() throws Exception {

        fidoAuthenticator = FIDOAuthenticator.getInstance();
        MockitoAnnotations.openMocks(this);

        identityUtilMock = mockStatic(IdentityUtil.class);
        fidoUtilMock = mockStatic(FIDOUtil.class);
        fidoAuthenticatorServiceComponentMock = mockStatic(FIDOAuthenticatorServiceComponent.class);

        fidoAuthenticatorServiceComponentMock.when(FIDOAuthenticatorServiceComponent::getRealmService)
                .thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        // User exists in the primary store, so the secondary-store domain resolution loop is skipped.
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);

        // FIDOUtil.getUsernameWithoutDomain is a passthrough for non-domain-qualified usernames.
        fidoUtilMock.when(() -> FIDOUtil.getUsernameWithoutDomain(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @AfterMethod
    public void tearDown() {

        if (identityUtilMock != null) {
            identityUtilMock.close();
        }
        if (fidoUtilMock != null) {
            fidoUtilMock.close();
        }
        if (fidoAuthenticatorServiceComponentMock != null) {
            fidoAuthenticatorServiceComponentMock.close();
        }
    }

    private AuthenticationContext context() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        return context;
    }

    private AuthenticatedUser authenticatedUser(String username) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(username);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        return user;
    }

    @Test(description = "Case-insensitive store + resolver returns canonical username -> username " +
            "normalized to the stored case.")
    public void testNormalizesUsernameWhenStoreCaseInsensitive() throws Exception {

        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(USER_STORE_DOMAIN, TENANT_ID))
                .thenReturn(false);

        try (MockedConstruction<WebAuthnService> ignored = Mockito.mockConstruction(WebAuthnService.class,
                (mock, ctx) -> when(mock.resolveStoredUsername(REQUEST_USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN))
                        .thenReturn(STORED_USERNAME))) {

            AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(
                    context(), authenticatedUser(REQUEST_USERNAME));

            Assert.assertEquals(result.getUserName(), STORED_USERNAME,
                    "Username should be normalized to the enrolled passkey's stored case.");
        }
    }

    @Test(description = "Store is case-SENSITIVE -> guard blocks resolution, username unchanged.")
    public void testDoesNotNormalizeWhenStoreCaseSensitive() throws Exception {

        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(USER_STORE_DOMAIN, TENANT_ID))
                .thenReturn(true);

        try (MockedConstruction<WebAuthnService> construction = Mockito.mockConstruction(WebAuthnService.class)) {

            AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(
                    context(), authenticatedUser(REQUEST_USERNAME));

            Assert.assertEquals(result.getUserName(), REQUEST_USERNAME,
                    "On a case-sensitive store the username must be preserved verbatim.");
            Assert.assertTrue(construction.constructed().isEmpty(),
                    "The passkey resolver must not be invoked on a case-sensitive store.");
        }
    }

    @Test(description = "Case-insensitive store but resolver returns null (no enrolled passkey) -> " +
            "username unchanged so genuine progressive enrollment still occurs.")
    public void testDoesNotNormalizeWhenResolverReturnsNull() throws Exception {

        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(USER_STORE_DOMAIN, TENANT_ID))
                .thenReturn(false);

        try (MockedConstruction<WebAuthnService> ignored = Mockito.mockConstruction(WebAuthnService.class,
                (mock, ctx) -> when(mock.resolveStoredUsername(REQUEST_USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN))
                        .thenReturn(null))) {

            AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(
                    context(), authenticatedUser(REQUEST_USERNAME));

            Assert.assertEquals(result.getUserName(), REQUEST_USERNAME,
                    "With no enrolled passkey the request username must be preserved.");
        }
    }

    @Test(description = "Case-insensitive store but resolver returns blank -> username unchanged.")
    public void testDoesNotNormalizeWhenResolverReturnsBlank() throws Exception {

        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(USER_STORE_DOMAIN, TENANT_ID))
                .thenReturn(false);

        try (MockedConstruction<WebAuthnService> ignored = Mockito.mockConstruction(WebAuthnService.class,
                (mock, ctx) -> when(mock.resolveStoredUsername(REQUEST_USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN))
                        .thenReturn("   "))) {

            AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(
                    context(), authenticatedUser(REQUEST_USERNAME));

            Assert.assertEquals(result.getUserName(), REQUEST_USERNAME,
                    "A blank resolver result must not overwrite the request username.");
        }
    }

    @Test(description = "Case-insensitive store but resolver hits a server error -> the flow fails " +
            "instead of silently authenticating with the un-normalized username.",
            expectedExceptions = AuthenticationFailedException.class)
    public void testFailsWhenResolverThrowsServerException() throws Exception {

        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(USER_STORE_DOMAIN, TENANT_ID))
                .thenReturn(false);

        try (MockedConstruction<WebAuthnService> ignored = Mockito.mockConstruction(WebAuthnService.class,
                (mock, ctx) -> when(mock.resolveStoredUsername(REQUEST_USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN))
                        .thenThrow(new FIDO2AuthenticatorServerException("DB error", new RuntimeException("boom"))))) {

            fidoAuthenticator.normalizeAuthenticatedUser(context(), authenticatedUser(REQUEST_USERNAME));
        }
    }
}
