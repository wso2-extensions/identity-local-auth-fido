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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2ExecutorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.base.CarbonBaseConstants.CARBON_CONFIG_DIR_PATH;
import static org.wso2.carbon.base.CarbonBaseConstants.CARBON_HOME;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@PrepareForTest({CarbonContext.class, PrivilegedCarbonContext.class, FIDO2Executor.class,
        WebAuthnService.class, FIDOUtil.class, UserCoreUtil.class, JsonParser.class})
public class FIDO2ExecutorTest {

    private static final String ORIGIN = "https://localhost:9443";
    private static final String USERNAME = "admin";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TENANT_QUALIFIED_USERNAME = "admin@carbon.super";
    private static final String DISPLAY_NAME = "Administrator";
    private static final String FIRST_NAME = "admin";
    private static final String LAST_NAME = "admin";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String CREDENTIAL_ID = "ATfjfbakUOSN_bz0bFThKAL9nA8FtZVKsKLZr1-ab6kGSiG36eIU8pHnG38sbgmg3U5" +
            "ad7QFULle0ee0vn2rwah74_IuSjsWL_3LNgk8emvOcBppGO1dqB6tQsllRQg";
    private static final String REQUEST_ID = "dgyt765RrfdH#";

    private FIDO2Executor fido2Executor;

    @Mock
    private WebAuthnService webAuthnService;
    @Mock
    private FlowExecutionContext flowExecutionContext;
    @Mock
    private FlowUser flowUser;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        fido2Executor = new FIDO2Executor();
        mockCarbonContext();

        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn(TENANT_QUALIFIED_USERNAME);

        // Setup FlowExecutionContext mocks
        when(flowExecutionContext.getFlowUser()).thenReturn(flowUser);
        when(flowUser.getUsername()).thenReturn(USERNAME);

        // Initialize empty maps for user claims, properties, and input data
        Map<String, String> claimMap = new HashMap<>();
        Map<String, Object> propertyMap = new HashMap<>();
        Map<String, String> inputDataMap = new HashMap<>();

        when(flowUser.getClaims()).thenReturn(claimMap);
        when(flowExecutionContext.getProperties()).thenReturn(propertyMap);
        when(flowExecutionContext.getUserInputData()).thenReturn(inputDataMap);

        // Mock FIDOUtil
        mockStatic(FIDOUtil.class);
        when(FIDOUtil.writeJson(any())).thenReturn("{\"key\":\"value\"}");

        // Set the webAuthnService in the FIDO2Executor using reflection
        setWebAuthnServiceInExecutor();
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(fido2Executor.getName(), "FIDO2Executor");
    }

    @Test
    public void testGetInitiationData() {

        List<String> initiationData = fido2Executor.getInitiationData();
        Assert.assertEquals(initiationData, Arrays.asList(FIDO2ExecutorConstants.ORIGIN, USERNAME_CLAIM));
    }

    @Test
    public void testExecuteWithoutOrigin() {

        Map<String, String> inputData = new HashMap<>();
        when(flowExecutionContext.getUserInputData()).thenReturn(inputData);
        when(flowUser.getUsername()).thenReturn(USERNAME);
        ExecutorResponse response = fido2Executor.execute(flowExecutionContext);
        Assert.assertEquals(response.getResult(), STATUS_CLIENT_INPUT_REQUIRED);
        Assert.assertTrue(response.getRequiredData().contains(FIDO2ExecutorConstants.ORIGIN));
    }

    @Test
    public void testProcessFIDO2WithValidCredential() throws Exception {
        // Setup
        Map<String, Object> properties = new HashMap<>();
        properties.put(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY, REQUEST_ID);
        properties.put(FIDO2ExecutorConstants.ORIGIN, ORIGIN);
        when(flowExecutionContext.getProperties()).thenReturn(properties);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY)).thenReturn(REQUEST_ID);

        Map<String, String> inputData = new HashMap<>();
        String credential = "{\"id\":\"" + CREDENTIAL_ID + "\",\"type\":\"public-key\"}";
        inputData.put(FIDO2ExecutorConstants.CREDENTIAL, credential);
        when(flowExecutionContext.getUserInputData()).thenReturn(inputData);

        mockStatic(JsonParser.class);
        JsonObject credentialJson = new JsonObject();
        credentialJson.addProperty(FIDO2ExecutorConstants.ID, CREDENTIAL_ID);
        when(JsonParser.parseString(credential)).thenReturn(credentialJson);

        ExecutorResponse response = fido2Executor.execute(flowExecutionContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
        Assert.assertEquals(response.getContextProperties().get(FIDO2ExecutorConstants.CREDENTIAL_ID), CREDENTIAL_ID);
    }

    @Test
    public void testProcessFIDO2WithError() throws Exception {
        // Setup
        Map<String, Object> properties = new HashMap<>();
        properties.put(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY, REQUEST_ID);
        properties.put(FIDO2ExecutorConstants.ORIGIN, ORIGIN);
        when(flowExecutionContext.getProperties()).thenReturn(properties);
        when(flowExecutionContext.getProperty(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY)).thenReturn(REQUEST_ID);

        Map<String, String> inputData = new HashMap<>();
        String credential = "{\"id\":\"" + CREDENTIAL_ID + "\",\"type\":\"public-key\"}";
        inputData.put(FIDO2ExecutorConstants.CREDENTIAL, credential);
        when(flowExecutionContext.getUserInputData()).thenReturn(inputData);

        mockStatic(JsonParser.class);
        JsonObject credentialJson = new JsonObject();
        credentialJson.addProperty(FIDO2ExecutorConstants.ID, CREDENTIAL_ID);
        when(JsonParser.parseString(credential)).thenReturn(credentialJson);

        // Set up WebAuthnService to throw an exception
        doThrow(new FIDO2AuthenticatorClientException("Error processing credential", ""))
                .when(webAuthnService).finishFIDO2Registration(anyString(), anyString());

        ExecutorResponse response = fido2Executor.execute(flowExecutionContext);

        Assert.assertEquals(response.getResult(), STATUS_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "Error processing credential");
    }

    @Test
    public void testRollbackWithCredential() throws Exception {
        // Setup
        Map<String, Object> properties = new HashMap<>();
        properties.put(FIDO2ExecutorConstants.CREDENTIAL_ID, CREDENTIAL_ID);
        when(flowExecutionContext.getProperties()).thenReturn(properties);
        when(flowUser.getUsername()).thenReturn(USERNAME);

        ExecutorResponse response = fido2Executor.rollback(flowExecutionContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testRollbackWithError() throws Exception {
        // Setup
        Map<String, Object> properties = new HashMap<>();
        properties.put(FIDO2ExecutorConstants.CREDENTIAL_ID, CREDENTIAL_ID);
        when(flowExecutionContext.getProperties()).thenReturn(properties);
        when(flowUser.getUsername()).thenReturn(USERNAME);

        // Set up WebAuthnService to throw an exception
        doThrow(new FIDO2AuthenticatorClientException("Error deregistering credential", ""))
                .when(webAuthnService).deregisterFIDO2Credential(anyString(), anyString());

        ExecutorResponse response = fido2Executor.rollback(flowExecutionContext);

        Assert.assertEquals(response.getResult(), STATUS_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "Error deregistering credential");
    }

    private void setWebAuthnServiceInExecutor() {

        try {
            Field field = FIDO2Executor.class.getDeclaredField("webAuthnService");
            field.setAccessible(true);
            field.set(fido2Executor, webAuthnService);
        } catch (Exception e) {
            // Handle exception, if needed
            e.printStackTrace();
        }
    }

    private void mockCarbonContext() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CARBON_HOME, carbonHome);
        System.setProperty(CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());

        mockStatic(PrivilegedCarbonContext.class);
        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        when(privilegedCarbonContext.getTenantId()).thenReturn(SUPER_TENANT_ID);
        when(privilegedCarbonContext.getUsername()).thenReturn(USERNAME);

        mockStatic(CarbonContext.class);
        CarbonContext carbonContext = mock(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn(USERNAME);
        when(carbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
    }

    private static String readResource(String filename, Class cClass) throws IOException {

        try (InputStream resourceAsStream = cClass.getResourceAsStream(filename);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(resourceAsStream)) {
            StringBuilder resourceFile = new StringBuilder();

            int character;
            while ((character = bufferedInputStream.read()) != -1) {
                char value = (char) character;
                resourceFile.append(value);
            }

            return resourceFile.toString();
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }
}
