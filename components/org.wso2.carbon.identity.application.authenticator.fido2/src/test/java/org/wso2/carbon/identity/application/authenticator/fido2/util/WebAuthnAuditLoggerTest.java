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
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuditLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.verifyStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit test class for WebAuthnAuditLogger class.
 */
@PrepareForTest({CarbonContext.class, UserCoreUtil.class, MultitenantUtils.class,
                IdentityUtil.class, LoggerUtils.class})
public class WebAuthnAuditLoggerTest {

    private WebAuthnAuditLogger auditLogger;

    @Mock
    private CarbonContext carbonContext;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {
        System.setProperty("carbon.home", ".");
        initMocks(this);
        auditLogger = new WebAuthnAuditLogger();

        mockStatic(CarbonContext.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityUtil.class);
        mockStatic(LoggerUtils.class);

        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn("testUser");
        when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
        when(UserCoreUtil.addTenantDomainToEntry("testUser", "carbon.super"))
                .thenReturn("testUser@carbon.super");
        when(MultitenantUtils.getTenantAwareUsername("testUser@carbon.super"))
                .thenReturn("testUser");
        when(MultitenantUtils.getTenantDomain("testUser@carbon.super"))
                .thenReturn("carbon.super");
        when(IdentityUtil.getInitiatorId("testUser", "carbon.super"))
                .thenReturn("initiator-id-test");
        when(LoggerUtils.getInitiatorType(anyString()))
                .thenReturn("User");

        Map<String, Object> mockMap = new HashMap<>();
        when(LoggerUtils.jsonObjectToMap(any(JSONObject.class)))
                .thenReturn(mockMap);
    }

    /**
     * Test the private method 'getUser' for a regular, tenant-aware user.
     */
    @Test
    public void testGetUserRegularUser() throws Exception {
        // Act: Invoke the private method using reflection.
        Method getUserMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getUser");
        getUserMethod.setAccessible(true);
        String result = (String) getUserMethod.invoke(auditLogger);

        // Assert
        Assert.assertEquals(result, "testUser@carbon.super");
    }

    /**
     * Test the private method 'getInitiatorId' with valid user data.
     */
    @Test
    public void testGetInitiatorIdWithValidUser() throws Exception {
        // Act
        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);

        // Assert
        Assert.assertEquals(result, "initiator-id-test");
    }

    /**
     * Test the private method 'getInitiatorId' when IdentityUtil returns blank initiator.
     */
    @Test
    public void testGetInitiatorIdWithBlankInitiator() throws Exception {
        // Arrange
        when(IdentityUtil.getInitiatorId("testUser", "carbon.super"))
                .thenReturn("");
        when(LoggerUtils.getMaskedContent("testUser@carbon.super"))
                .thenReturn("masked-user");

        // Act
        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);

        // Assert
        Assert.assertEquals(result, "masked-user");
    }

    /**
     * Test the private method 'getInitiatorId' for system user.
     */
    @Test
    public void testGetInitiatorIdWithSystemUser() throws Exception {
        // Arrange
        when(carbonContext.getUsername()).thenReturn(CarbonConstants.REGISTRY_SYSTEM_USERNAME);
        when(UserCoreUtil.addTenantDomainToEntry(
                CarbonConstants.REGISTRY_SYSTEM_USERNAME, "carbon.super"))
                .thenReturn(CarbonConstants.REGISTRY_SYSTEM_USERNAME + "@carbon.super");
        when(MultitenantUtils.getTenantAwareUsername(
                CarbonConstants.REGISTRY_SYSTEM_USERNAME + "@carbon.super"))
                .thenReturn(CarbonConstants.REGISTRY_SYSTEM_USERNAME);
        when(IdentityUtil.getInitiatorId(
                CarbonConstants.REGISTRY_SYSTEM_USERNAME, "carbon.super"))
                .thenReturn("");

        // Act
        Method getInitiatorIdMethod = WebAuthnAuditLogger.class.getDeclaredMethod("getInitiatorId");
        getInitiatorIdMethod.setAccessible(true);
        String result = (String) getInitiatorIdMethod.invoke(auditLogger);

        // Assert
        Assert.assertEquals(result, LoggerUtils.Initiator.System.name());
    }

    /**
     * Test the private method 'createAuditLogEntry' with valid data.
     */
    @Test
    public void testCreateAuditLogEntryWithValidData() throws Exception {
        // Arrange
        String username = "testUser@carbon.super";
        String credentialId = "credential-123";
        String initiator = "admin";

        // Act
        Method createAuditLogEntryMethod = WebAuthnAuditLogger.class.getDeclaredMethod("createAuditLogEntry",
                String.class, String.class, String.class);
        createAuditLogEntryMethod.setAccessible(true);
        JSONObject result = (JSONObject) createAuditLogEntryMethod.invoke(auditLogger, username, credentialId, initiator);

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getString("Username"), username);
        Assert.assertEquals(result.getString("CredentialId"), credentialId);
        Assert.assertEquals(result.getString("Initiator"), initiator);
    }

    /**
     * Test the public method 'printAuditLog' with valid data.
     */
    @Test
    public void testPrintAuditLogWithValidData() {
        // Arrange
        String username = "testUser@carbon.super";
        String credentialId = "credential-123";
        String initiator = "admin";
        WebAuthnAuditLogger.Operation operation = WebAuthnAuditLogger.Operation.DEREGISTER_DEVICE;

        // Act
        auditLogger.printAuditLog(operation, username, credentialId, initiator);

        // Assert - Verify that triggerAuditLogEvent was called
        verifyStatic();
        LoggerUtils.triggerAuditLogEvent(any(AuditLog.AuditLogBuilder.class));
    }

    /**
     * Test the Operation enum values.
     */
    @Test
    public void testOperationEnum() {
        // Act & Assert
        WebAuthnAuditLogger.Operation operation = WebAuthnAuditLogger.Operation.DEREGISTER_DEVICE;
        Assert.assertEquals(operation.getLogAction(), "deregister-device");
    }

    /**
     * Test the private method 'buildAuditLog' to ensure proper audit log building.
     */
    @Test
    public void testBuildAuditLog() throws Exception {
        // Arrange
        WebAuthnAuditLogger.Operation operation = WebAuthnAuditLogger.Operation.DEREGISTER_DEVICE;
        JSONObject data = new JSONObject();
        data.put("Username", "testUser@carbon.super");
        data.put("CredentialId", "credential-123");
        data.put("Initiator", "admin");

        // Act
        Method buildAuditLogMethod = WebAuthnAuditLogger.class.getDeclaredMethod("buildAuditLog",
                WebAuthnAuditLogger.Operation.class, JSONObject.class);
        buildAuditLogMethod.setAccessible(true);
        buildAuditLogMethod.invoke(auditLogger, operation, data);

        // Assert - Verify that triggerAuditLogEvent was called
        verifyStatic();
        LoggerUtils.triggerAuditLogEvent(any(AuditLog.AuditLogBuilder.class));

        verifyStatic();
        LoggerUtils.jsonObjectToMap(any(JSONObject.class));
    }
}
