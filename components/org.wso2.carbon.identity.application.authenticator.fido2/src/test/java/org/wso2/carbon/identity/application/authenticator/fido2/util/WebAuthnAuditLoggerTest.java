/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.fido2.util;

import org.json.JSONObject;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Method;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

/**
 * Unit test class for WebAuthnAuditLogger class.
 */
public class WebAuthnAuditLoggerTest {

    private static final String TEST_USER = "testUser";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_USER_ID = "user-id-123";
    private static final String TEST_CREDENTIAL_ID = "credential-id-123";

    private WebAuthnAuditLogger auditLogger;
    private CarbonContext carbonContext;
    private PrivilegedCarbonContext privilegedCarbonContext;

    private MockedStatic<CarbonContext> mockedCarbonContext;
    private MockedStatic<PrivilegedCarbonContext> mockedPrivilegedCarbonContext;
    private MockedStatic<UserCoreUtil> mockedUserCoreUtil;
    private MockedStatic<MultitenantUtils> mockedMultitenantUtils;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<LoggerUtils> mockedLoggerUtils;
    private MockedStatic<FIDO2AuthenticatorServiceDataHolder> mockedDataHolder;

    @BeforeMethod
    public void setUp() throws Exception {

        System.setProperty("carbon.home", ".");
        MockitoAnnotations.openMocks(this);
        auditLogger = new WebAuthnAuditLogger();

        mockedCarbonContext = mockStatic(CarbonContext.class);
        mockedPrivilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
        mockedMultitenantUtils = mockStatic(MultitenantUtils.class);
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedDataHolder = mockStatic(FIDO2AuthenticatorServiceDataHolder.class);

        carbonContext = mock(CarbonContext.class);
        mockedCarbonContext.when(CarbonContext::getThreadLocalCarbonContext).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn(TEST_USER);
        when(carbonContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

        privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        mockedPrivilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        when(privilegedCarbonContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

        mockedUserCoreUtil.when(() -> UserCoreUtil.addTenantDomainToEntry(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "@" + invocation.getArgument(1));

        mockedIdentityUtil.when(() -> IdentityUtil.getInitiatorId(anyString(), anyString()))
                .thenReturn("initiator-id-test");

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(SUPER_TENANT_ID);

        FIDO2AuthenticatorServiceDataHolder dataHolder = mock(FIDO2AuthenticatorServiceDataHolder.class);
        RealmService realmService = mock(RealmService.class);
        UserRealm userRealm = mock(UserRealm.class);
        AbstractUserStoreManager userStoreManager = mock(AbstractUserStoreManager.class);

        mockedDataHolder.when(FIDO2AuthenticatorServiceDataHolder::getInstance).thenReturn(dataHolder);
        when(dataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserIDFromUserName(anyString())).thenReturn(TEST_USER_ID);

        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString()))
                .thenAnswer(invocation -> {
                    String username = invocation.getArgument(0);
                    if (username != null && username.contains("@")) {
                        return username.substring(0, username.lastIndexOf("@"));
                    }
                    return username;
                });
    }

    @AfterMethod
    public void tearDown() {

        mockedCarbonContext.close();
        mockedPrivilegedCarbonContext.close();
        mockedUserCoreUtil.close();
        mockedMultitenantUtils.close();
        mockedIdentityUtil.close();
        mockedIdentityTenantUtil.close();
        mockedLoggerUtils.close();
        mockedDataHolder.close();
    }

    /**
     * Test the private method 'getUser' for a regular, tenant-aware user.
     */
    @Test
    public void testGetUserRegularUser() throws Exception {

        Method getUserMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getUser");
        getUserMethod.setAccessible(true);
        String result = (String) getUserMethod.invoke(auditLogger);
        Assert.assertEquals(result, TEST_USER + "@" + TEST_TENANT_DOMAIN);
    }

    /**
     * Test the private method 'getUser' for the system user.
     */
    @Test
    public void testGetUserWithSystemUser() throws Exception {

        when(carbonContext.getUsername()).thenReturn("");
        Method getUserMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getUser");
        getUserMethod.setAccessible(true);
        String result = (String) getUserMethod.invoke(auditLogger);
        Assert.assertEquals(result, CarbonConstants.REGISTRY_SYSTEM_USERNAME);
    }

    /**
     * Test the private method 'getUser' when username is null.
     */
    @Test
    public void testGetUserWithNullUsername() throws Exception {

        when(carbonContext.getUsername()).thenReturn(null);
        Method getUserMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getUser");
        getUserMethod.setAccessible(true);
        String result = (String) getUserMethod.invoke(auditLogger);
        Assert.assertEquals(result, CarbonConstants.REGISTRY_SYSTEM_USERNAME);
    }

    /**
     * Test the private method 'createAuditLogEntry' with valid data.
     */
    @Test
    public void testCreateAuditLogEntryWithValidData() throws Exception {

        String username = "testuser@carbon.super";
        Method createAuditLogEntryMethod = WebAuthnAuditLogger.class.getDeclaredMethod("createAuditLogEntry",
                String.class);
        createAuditLogEntryMethod.setAccessible(true);
        JSONObject result = (JSONObject) createAuditLogEntryMethod.invoke(auditLogger, username);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getString("UserId"), TEST_USER_ID);
        Assert.assertTrue(result.has("DeregisteredAt"));
    }

    /**
     * Test the private method 'createAuditLogEntry' with null username.
     */
    @Test
    public void testCreateAuditLogEntryWithNullUsername() throws Exception {

        Method createAuditLogEntryMethod = WebAuthnAuditLogger.class.getDeclaredMethod("createAuditLogEntry",
                String.class);
        createAuditLogEntryMethod.setAccessible(true);
        JSONObject result = (JSONObject) createAuditLogEntryMethod.invoke(auditLogger, (String) null);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isNull("UserId"));
        Assert.assertTrue(result.has("DeregisteredAt"));
    }

    /**
     * Test the private method 'getInitiatorId' returns valid initiator ID.
     */
    @Test
    public void testGetInitiatorId() throws Exception {

        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);
        Assert.assertNotNull(result);
        Assert.assertEquals(result, "initiator-id-test");
    }

    /**
     * Test the private method 'getInitiatorId' when initiator ID is blank.
     */
    @Test
    public void testGetInitiatorIdWhenBlank() throws Exception {

        mockedIdentityUtil.when(() -> IdentityUtil.getInitiatorId(anyString(), anyString()))
                .thenReturn("");
        mockedLoggerUtils.when(() -> LoggerUtils.getMaskedContent(anyString()))
                .thenReturn("masked-user");

        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);
        Assert.assertNotNull(result);
        Assert.assertEquals(result, "masked-user");
    }

    /**
     * Test the private method 'getInitiatorId' for system user.
     */
    @Test
    public void testGetInitiatorIdForSystemUser() throws Exception {

        when(carbonContext.getUsername()).thenReturn("");
        mockedIdentityUtil.when(() -> IdentityUtil.getInitiatorId(anyString(), anyString()))
                .thenReturn("");

        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);
        Assert.assertNotNull(result);
        Assert.assertEquals(result, LoggerUtils.Initiator.System.name());
    }

    /**
     * Test the private method 'resolveUserIdFromUsername' with valid username.
     */
    @Test
    public void testResolveUserIdFromUsername() throws Exception {

        String username = "testuser@carbon.super";
        Method resolveUserIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("resolveUserIdFromUsername",
                String.class);
        resolveUserIdMethod.setAccessible(true);
        String result = (String) resolveUserIdMethod.invoke(auditLogger, username);
        Assert.assertNotNull(result);
        Assert.assertEquals(result, TEST_USER_ID);
    }

    /**
     * Test the Operation enum values.
     */
    @Test
    public void testOperationEnumValues() {

        Assert.assertEquals(WebAuthnAuditLogger.Operation.DEREGISTER_PASSKEY.getLogAction(), "Deregister-Passkey");
    }
}
