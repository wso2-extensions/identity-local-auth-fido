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

package org.wso2.carbon.identity.application.authenticator.fido2.executor;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2ExecutorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for RegistrationFlowCompletionListener.
 */
public class RegistrationFlowCompletionListenerTest {

    private static final String USERNAME = "testuser";
    private static final String CONTEXT_IDENTIFIER = "test-flow-123";
    private static final String CREDENTIAL_ID = "test-credential-id";
    private static final String DISPLAY_NAME = "Test Device";
    private static final long SIGNATURE_COUNT = 1L;
    private static final String REGISTRATION_TIME_STRING = "2025-01-01T10:00:00Z";

    private RegistrationFlowCompletionListener listener;
    private AutoCloseable openMocks;
    private MockedStatic<FIDOUtil> fidoUtilStatic;
    private MockedStatic<FIDO2DeviceStoreDAO> deviceStoreStatic;

    @Mock
    private FlowExecutionStep flowExecutionStep;

    @Mock
    private FlowExecutionContext flowExecutionContext;

    @Mock
    private FlowUser flowUser;

    @Mock
    private FIDO2DeviceStoreDAO deviceStoreDAO;

    @BeforeMethod
    public void setUp() {

        openMocks = MockitoAnnotations.openMocks(this);
        listener = new RegistrationFlowCompletionListener();

        fidoUtilStatic = Mockito.mockStatic(FIDOUtil.class);
        deviceStoreStatic = Mockito.mockStatic(FIDO2DeviceStoreDAO.class);
        deviceStoreStatic.when(FIDO2DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(flowExecutionContext.getFlowUser()).thenReturn(flowUser);
        when(flowUser.getUsername()).thenReturn(USERNAME);
        when(flowExecutionContext.getContextIdentifier()).thenReturn(CONTEXT_IDENTIFIER);
    }

    @AfterMethod(alwaysRun = true)
    public void tearDown() throws Exception {
        if (fidoUtilStatic != null) {
            fidoUtilStatic.close();
        }
        if (deviceStoreStatic != null) {
            deviceStoreStatic.close();
        }
        if (openMocks != null) {
            openMocks.close();
        }
    }

    @Test
    public void testGetExecutionOrderId() {

        Assert.assertEquals(listener.getExecutionOrderId(), 5);
    }

    @Test
    public void testGetDefaultOrderId() {

        Assert.assertEquals(listener.getDefaultOrderId(), 5);
    }

    @Test
    public void testIsEnabled() {

        Assert.assertTrue(listener.isEnabled());
    }

    @Test
    public void testDoPostExecuteWithRegistrationFlowAndCompleteStatus() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testDoPostExecuteWithNonRegistrationFlow() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(false);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
    }

    @Test
    public void testDoPostExecuteWithIncompleteStatus() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_INCOMPLETE);
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
    }

    @Test
    public void testDoPostExecuteWithNullCredentialRegistration() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(null);
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
    }

    @Test
    public void testDoPostExecuteWithDAOException() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);

        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doThrow(new FIDO2AuthenticatorServerException("DAO error", new Exception("Test exception")))
                .when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithCompleteData() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);

        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithMinimalData() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);

        Map<String, Object> credentialRegistrationMap = createMinimalCredentialRegistrationMap();
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithNullOptionalFields() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        Map<String, Object> credentialRegistrationMap = createCredentialRegistrationMapWithNulls();
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithoutRegistrationTime() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        credentialRegistrationMap.remove(FIDO2ExecutorConstants.RegistrationConstants.REGISTRATION_TIME);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithZeroSignatureCount() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        credentialRegistrationMap.put(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT, null);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    @Test
    public void testBuildFromMapWithUsernamelessSupported() throws Exception {

        fidoUtilStatic.when(() -> FIDOUtil.isRegistrationFlow(flowExecutionContext)).thenReturn(true);
        when(flowExecutionStep.getFlowStatus()).thenReturn(Constants.STATUS_COMPLETE);
        Map<String, Object> credentialRegistrationMap = createTestCredentialRegistrationMap();
        credentialRegistrationMap.put(FIDO2ExecutorConstants.RegistrationConstants.IS_USERNAMELESS_SUPPORTED, true);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION))
                .thenReturn(credentialRegistrationMap);
        doNothing().when(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
        boolean result = listener.doPostExecute(flowExecutionStep, flowExecutionContext);
        Assert.assertTrue(result);
        verify(deviceStoreDAO).addFIDO2RegistrationByUsername(eq(USERNAME), any(FIDO2CredentialRegistration.class));
    }

    /**
     * Helper method to create a complete credential registration map for testing.
     */
    private Map<String, Object> createTestCredentialRegistrationMap() {

        Map<String, Object> map = new HashMap<>();
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put("credentialId", CREDENTIAL_ID);
        credentialMap.put("userHandle", "test-user-handle");
        credentialMap.put("publicKeyCose", "test-public-key");
        credentialMap.put("signatureCount", SIGNATURE_COUNT);
        map.put(FIDO2ExecutorConstants.CREDENTIAL, credentialMap);
        Map<String, Object> userIdentityMap = new HashMap<>();
        userIdentityMap.put("name", USERNAME);
        userIdentityMap.put("displayName", "Test User");
        userIdentityMap.put("id", "test-user-id");
        map.put(FIDO2ExecutorConstants.RegistrationConstants.USER_IDENTITY, userIdentityMap);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.CREDENTIAL_NICKNAME, "Test Nickname");
        map.put(FIDO2ExecutorConstants.RegistrationConstants.ATTESTATION_METADATA, null);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT, SIGNATURE_COUNT);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.DISPLAY_NAME, DISPLAY_NAME);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.IS_USERNAMELESS_SUPPORTED, false);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.REGISTRATION_TIME, REGISTRATION_TIME_STRING);
        return map;
    }

    /**
     * Helper method to create a minimal credential registration map for testing.
     */
    private Map<String, Object> createMinimalCredentialRegistrationMap() {

        Map<String, Object> map = new HashMap<>();
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put("credentialId", CREDENTIAL_ID);
        credentialMap.put("userHandle", "test-user-handle");
        credentialMap.put("publicKeyCose", "test-public-key");
        credentialMap.put("signatureCount", 0L);
        map.put(FIDO2ExecutorConstants.CREDENTIAL, credentialMap);

        Map<String, Object> userIdentityMap = new HashMap<>();
        userIdentityMap.put("name", USERNAME);
        userIdentityMap.put("displayName", USERNAME);
        userIdentityMap.put("id", "test-user-id");
        map.put(FIDO2ExecutorConstants.RegistrationConstants.USER_IDENTITY, userIdentityMap);

        map.put(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT, 0L);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.DISPLAY_NAME, USERNAME);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.IS_USERNAMELESS_SUPPORTED, false);

        return map;
    }

    /**
     * Helper method to create a credential registration map with null optional fields.
     */
    private Map<String, Object> createCredentialRegistrationMapWithNulls() {

        Map<String, Object> map = new HashMap<>();

        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put("credentialId", CREDENTIAL_ID);
        credentialMap.put("userHandle", "test-user-handle");
        credentialMap.put("publicKeyCose", "test-public-key");
        credentialMap.put("signatureCount", SIGNATURE_COUNT);
        map.put(FIDO2ExecutorConstants.CREDENTIAL, credentialMap);

        Map<String, Object> userIdentityMap = new HashMap<>();
        userIdentityMap.put("name", USERNAME);
        userIdentityMap.put("displayName", "Test User");
        userIdentityMap.put("id", "test-user-id");
        map.put(FIDO2ExecutorConstants.RegistrationConstants.USER_IDENTITY, userIdentityMap);

        map.put(FIDO2ExecutorConstants.RegistrationConstants.CREDENTIAL_NICKNAME, null);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.ATTESTATION_METADATA, null);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT, SIGNATURE_COUNT);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.DISPLAY_NAME, null);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.IS_USERNAMELESS_SUPPORTED, false);
        map.put(FIDO2ExecutorConstants.RegistrationConstants.REGISTRATION_TIME, null);

        return map;
    }
}
