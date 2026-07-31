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
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.BLOCKED_USERSTORE_DOMAINS_LIST;

/**
 * Tests for the {@code BlockedUserStoreDomains} handling in {@link FIDOAuthenticator#normalizeAuthenticatedUser}
 * (issue #28228).
 * <p>
 * Two behaviours are asserted. A user whose username also exists in a blocked domain must still resolve to a usable
 * domain, and a user who can only be found in a blocked domain must be flagged so the blocked handling in
 * {@code process} is not skipped. An unknown username must never be flagged, otherwise it becomes distinguishable
 * from a user who simply has no enrolled passkeys.
 * <p>
 * The store topology used throughout is PRIMARY -> SEC1 -> SEC2.
 */
public class FIDOAuthenticatorBlockedUserStoreDomainTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;

    private static final String PRIMARY_DOMAIN = "PRIMARY";
    private static final String SECONDARY_DOMAIN_ONE = "SEC1";
    private static final String SECONDARY_DOMAIN_TWO = "SEC2";

    private static final String USERNAME = "alice";
    private static final String USERNAME_IN_SECONDARY_ONE = "SEC1/alice";
    private static final String USERNAME_IN_SECONDARY_TWO = "SEC2/alice";

    private static final String IS_USER_STORE_DOMAIN_BLOCKED = "isUserStoreDomainBlocked";

    private FIDOAuthenticator fidoAuthenticator;

    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private UserRealm userRealm;
    @Mock
    private AbstractUserStoreManager primaryUserStoreManager;
    @Mock
    private UserStoreManager secondaryUserStoreManagerOne;
    @Mock
    private UserStoreManager secondaryUserStoreManagerTwo;
    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<FIDOUtil> fidoUtilMock;
    private MockedStatic<FIDOAuthenticatorServiceComponent> fidoAuthenticatorServiceComponentMock;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilderMock;

    @BeforeMethod
    public void setUp() throws Exception {

        fidoAuthenticator = FIDOAuthenticator.getInstance();
        MockitoAnnotations.openMocks(this);

        identityUtilMock = mockStatic(IdentityUtil.class);
        fidoUtilMock = mockStatic(FIDOUtil.class);
        fidoAuthenticatorServiceComponentMock = mockStatic(FIDOAuthenticatorServiceComponent.class);
        fileBasedConfigurationBuilderMock = mockStatic(FileBasedConfigurationBuilder.class);

        fidoAuthenticatorServiceComponentMock.when(FIDOAuthenticatorServiceComponent::getRealmService)
                .thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(primaryUserStoreManager);

        when(primaryUserStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration(PRIMARY_DOMAIN));
        when(secondaryUserStoreManagerOne.getRealmConfiguration())
                .thenReturn(realmConfiguration(SECONDARY_DOMAIN_ONE));
        when(secondaryUserStoreManagerTwo.getRealmConfiguration())
                .thenReturn(realmConfiguration(SECONDARY_DOMAIN_TWO));

        when(primaryUserStoreManager.getSecondaryUserStoreManager()).thenReturn(secondaryUserStoreManagerOne);
        when(secondaryUserStoreManagerOne.getSecondaryUserStoreManager()).thenReturn(secondaryUserStoreManagerTwo);
        when(secondaryUserStoreManagerTwo.getSecondaryUserStoreManager()).thenReturn(null);

        // The user exists nowhere unless a test says otherwise. Every existence check is routed through the primary
        // store manager, which is how the authenticator resolves domain qualified usernames.
        when(primaryUserStoreManager.isExistingUser(anyString())).thenReturn(false);

        // Keep the case normalization block inert. It is covered by FIDOAuthenticatorNormalizeUsernameTest.
        identityUtilMock.when(() -> IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);

        fidoUtilMock.when(() -> FIDOUtil.getUsernameWithoutDomain(anyString()))
                .thenAnswer(invocation -> {
                    String name = invocation.getArgument(0);
                    int separatorIndex = name.indexOf('/');
                    return separatorIndex < 0 ? name : name.substring(separatorIndex + 1);
                });

        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        givenBlockedUserStoreDomains(null);
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
        if (fileBasedConfigurationBuilderMock != null) {
            fileBasedConfigurationBuilderMock.close();
        }
    }

    @Test(description = "Username exists in the blocked primary store and in a usable secondary store -> resolves " +
            "to the secondary store so the enrolled passkey is found. This is the reported bug.")
    public void testResolvesToSecondaryWhenPrimaryDomainIsBlocked() throws Exception {

        givenBlockedUserStoreDomains(PRIMARY_DOMAIN);
        givenExistingUsers(USERNAME, USERNAME_IN_SECONDARY_ONE);

        AuthenticationContext context = context();
        AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertEquals(result.getUserStoreDomain(), SECONDARY_DOMAIN_ONE,
                "The user must resolve to the secondary store that holds the passkey, not the blocked primary.");
        Assert.assertFalse(isUserStoreDomainBlocked(context),
                "A user resolved to a usable domain must not be flagged as blocked.");
    }

    @Test(description = "Username exists only in the blocked primary store -> flagged as blocked so progressive " +
            "enrollment does not run against a domain the user is absent from.")
    public void testFlagsBlockedWhenUserOnlyExistsInBlockedPrimaryDomain() throws Exception {

        givenBlockedUserStoreDomains(PRIMARY_DOMAIN);
        givenExistingUsers(USERNAME);

        AuthenticationContext context = context();
        fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertTrue(isUserStoreDomainBlocked(context),
                "A user who exists only in a blocked domain must be flagged as blocked.");
    }

    @Test(description = "Username exists only in a blocked secondary store -> flagged as blocked. Blocking a " +
            "secondary store must behave the same as blocking the primary store.")
    public void testFlagsBlockedWhenUserOnlyExistsInBlockedSecondaryDomain() throws Exception {

        givenBlockedUserStoreDomains(SECONDARY_DOMAIN_ONE);
        givenExistingUsers(USERNAME_IN_SECONDARY_ONE);

        AuthenticationContext context = context();
        fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertTrue(isUserStoreDomainBlocked(context),
                "A user who exists only in a blocked secondary domain must be flagged as blocked.");
    }

    @Test(description = "Username exists in a blocked secondary store and in a usable one -> the walk continues " +
            "past the blocked store and resolves to the usable one.")
    public void testResolvesToUsableSecondaryWhenAnotherSecondaryDomainIsBlocked() throws Exception {

        givenBlockedUserStoreDomains(SECONDARY_DOMAIN_ONE);
        givenExistingUsers(USERNAME_IN_SECONDARY_ONE, USERNAME_IN_SECONDARY_TWO);

        AuthenticationContext context = context();
        AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertEquals(result.getUserStoreDomain(), SECONDARY_DOMAIN_TWO,
                "A blocked secondary store must not stop the walk at the first match.");
        Assert.assertFalse(isUserStoreDomainBlocked(context),
                "A user resolved to a usable domain must not be flagged as blocked.");
    }

    @Test(description = "Unknown username with a blocked domain configured -> not flagged, and the last walked " +
            "domain is still assigned, so the flow stays indistinguishable from a user with no passkeys.")
    public void testDoesNotFlagUnknownUsername() throws Exception {

        givenBlockedUserStoreDomains(PRIMARY_DOMAIN);

        AuthenticationContext context = context();
        AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertFalse(isUserStoreDomainBlocked(context),
                "An unknown username must never be flagged as blocked, that would leak whether it exists.");
        Assert.assertEquals(result.getUserStoreDomain(), SECONDARY_DOMAIN_TWO,
                "An unresolved user must keep the last walked domain rather than the incoming one.");
    }

    @Test(description = "Username exists in the primary store while only a secondary store is blocked -> untouched.")
    public void testDoesNotFlagPrimaryUserWhenOnlySecondaryDomainIsBlocked() throws Exception {

        givenBlockedUserStoreDomains(SECONDARY_DOMAIN_ONE);
        givenExistingUsers(USERNAME);

        AuthenticationContext context = context();
        AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertEquals(result.getUserStoreDomain(), PRIMARY_DOMAIN,
                "A user found in an unblocked primary store must keep the primary domain.");
        Assert.assertFalse(isUserStoreDomainBlocked(context),
                "A user in an unblocked domain must not be flagged as blocked.");
    }

    @Test(description = "No blocked domains configured -> resolution is unchanged and nothing is ever flagged. " +
            "This is the regression guard for deployments that do not set the configuration.")
    public void testResolutionUnchangedWhenNoDomainsAreBlocked() throws Exception {

        givenExistingUsers(USERNAME_IN_SECONDARY_ONE);

        AuthenticationContext context = context();
        AuthenticatedUser result = fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertEquals(result.getUserStoreDomain(), SECONDARY_DOMAIN_ONE,
                "Without the configuration the user must resolve exactly as before.");
        Assert.assertFalse(isUserStoreDomainBlocked(context),
                "Nothing can be blocked when no domains are configured.");
    }

    @Test(description = "Configured domains are trimmed and upper cased before comparison, so a value written " +
            "with spaces or in lower case still matches.")
    public void testTrimsAndUpperCasesConfiguredDomains() throws Exception {

        givenBlockedUserStoreDomains(" primary , sec1 ");
        givenExistingUsers(USERNAME);

        AuthenticationContext context = context();
        fidoAuthenticator.normalizeAuthenticatedUser(context, authenticatedUser());

        Assert.assertTrue(isUserStoreDomainBlocked(context),
                "A configured domain must match regardless of surrounding spaces and case.");
    }

    private AuthenticationContext context() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        return context;
    }

    private AuthenticatedUser authenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(USERNAME);
        user.setUserStoreDomain(PRIMARY_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        return user;
    }

    private RealmConfiguration realmConfiguration(String domainName) {

        RealmConfiguration realmConfiguration = new RealmConfiguration();
        Map<String, String> userStoreProperties = new HashMap<>();
        userStoreProperties.put(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME, domainName);
        realmConfiguration.setUserStoreProperties(userStoreProperties);
        return realmConfiguration;
    }

    private void givenBlockedUserStoreDomains(String blockedUserStoreDomains) {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameterMap = new HashMap<>();
        if (blockedUserStoreDomains != null) {
            parameterMap.put(BLOCKED_USERSTORE_DOMAINS_LIST, blockedUserStoreDomains);
        }
        authenticatorConfig.setParameterMap(parameterMap);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(FIDOAuthenticatorConstants.AUTHENTICATOR_NAME))
                .thenReturn(authenticatorConfig);
    }

    private void givenExistingUsers(String... existingUsernames) throws Exception {

        for (String existingUsername : existingUsernames) {
            when(primaryUserStoreManager.isExistingUser(existingUsername)).thenReturn(true);
        }
    }

    private boolean isUserStoreDomainBlocked(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(IS_USER_STORE_DOMAIN_BLOCKED));
    }
}
