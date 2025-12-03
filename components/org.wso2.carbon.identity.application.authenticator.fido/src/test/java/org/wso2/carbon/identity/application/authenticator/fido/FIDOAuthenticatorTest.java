/*
 * Copyright (c) 2022-2025, WSO2 LLC. (http://www.wso2.com).
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

import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.AUTHENTICATOR_FIDO;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;

public class FIDOAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private final String USERNAME = "admin";
    private final String SAMPLE_TOKEN_CHALLENGE = "sample_token_challenge";
    private FIDOAuthenticator fidoAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Spy
    private AuthenticationContext authenticationContext;
    @Mock
    private WebAuthnService webAuthnService;
    @Mock
    private U2FService u2FService;
    @Mock
    private AuthenticateResponse authenticateResponse;
    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    @Mock
    private AuthenticateRequestData authenticateRequestData;
    @Mock
    private ExternalIdPConfig externalIdPConfig;
    @Mock
    private AccountLockService mockAccountLockService;
    @Mock
    private FIDOAuthenticatorServiceDataHolder mockServiceDataHolder;

    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<U2FService> u2FServiceMock;
    private MockedStatic<AuthenticateResponse> authenticateResponseMock;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilderMock;
    private MockedStatic<URLEncoder> urlEncoderMock;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMock;
    private MockedStatic<LoggerUtils> loggerUtilsMock;
    private MockedStatic<FIDOAuthenticatorServiceDataHolder> fidoAuthenticatorServiceDataHolderMock;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilStatic;

    @BeforeMethod
    public void setUp() {

        fidoAuthenticator = FIDOAuthenticator.getInstance();
        MockitoAnnotations.openMocks(this);

        identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
        loggerUtilsMock = Mockito.mockStatic(LoggerUtils.class);
        fidoAuthenticatorServiceDataHolderMock = Mockito.mockStatic(FIDOAuthenticatorServiceDataHolder.class);
        identityTenantUtilStatic = Mockito.mockStatic(IdentityTenantUtil.class);

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        fidoAuthenticatorServiceDataHolderMock.when(FIDOAuthenticatorServiceDataHolder::getInstance)
                .thenReturn(mockServiceDataHolder);
        when(mockServiceDataHolder.getAccountLockService()).thenReturn(mockAccountLockService);
    }

    @AfterMethod
    public void tearDown() {

        if (identityUtilMock != null && !identityUtilMock.isClosed()) {
            identityUtilMock.close();
        }
        if (u2FServiceMock != null && !u2FServiceMock.isClosed()) {
            u2FServiceMock.close();
        }
        if (authenticateResponseMock != null && !authenticateResponseMock.isClosed()) {
            authenticateResponseMock.close();
        }
        if (fileBasedConfigurationBuilderMock != null && !fileBasedConfigurationBuilderMock.isClosed()) {
            fileBasedConfigurationBuilderMock.close();
        }
        if (urlEncoderMock != null && !urlEncoderMock.isClosed()) {
            urlEncoderMock.close();
        }
        if (serviceURLBuilderMock != null && !serviceURLBuilderMock.isClosed()) {
            serviceURLBuilderMock.close();
        }
        if (loggerUtilsMock != null && !loggerUtilsMock.isClosed()) {
            loggerUtilsMock.close();
        }
        if (fidoAuthenticatorServiceDataHolderMock != null && !fidoAuthenticatorServiceDataHolderMock.isClosed()) {
            fidoAuthenticatorServiceDataHolderMock.close();
        }
        if (identityTenantUtilStatic != null && !identityTenantUtilStatic.isClosed()) {
            identityTenantUtilStatic.close();
        }
    }

    private void mockServiceURLBuilder() {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("http://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        serviceURLBuilderMock = Mockito.mockStatic(ServiceURLBuilder.class);
        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    @Test(description = "Test case for canHandle() method true case.", priority = 1)
    public void testCanHandle() {

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        Assert.assertTrue(fidoAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for canHandle() method false case.", priority = 2)
    public void testCanHandleFalse() {

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
        Assert.assertFalse(fidoAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for successful logout request with valid token response.", priority = 3)
    public void testProcessLogoutRequestWithValidTokenResponse() throws Exception {

        when(authenticationContext.isLogoutRequest()).thenReturn(true);
        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        AuthenticatorFlowStatus status = fidoAuthenticator.process(
                httpServletRequest, httpServletResponse, authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for successful logout request with null token response.", priority = 4)
    public void testProcessLogoutRequestWithNullTokenResponse() throws Exception {

        when(authenticationContext.isLogoutRequest()).thenReturn(true);
        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
        AuthenticatorFlowStatus status = fidoAuthenticator.process(
                httpServletRequest, httpServletResponse, authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for usernameless processAuthenticationResponse() method when Webauthn is enabled",
            priority = 5)
    public void testProcessUsernamelessAuthenticationResponseWebauthnEnabled() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        identityTenantUtilStatic.when(() -> IdentityTenantUtil.getTenantId(eq("carbon.super"))).thenReturn(-1234);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(true));

        // Use MockedConstruction for WebAuthnService
        try (MockedConstruction<WebAuthnService> webAuthnServiceMockedConstruction = Mockito.mockConstruction(
                WebAuthnService.class, (mock, context1) -> {
                    when(mock.finishUsernamelessAuthentication(anyString())).thenReturn(authenticatedUser);
                })) {
            fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
            Assert.assertEquals(context.getSubject(), authenticatedUser);
            Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
        }
    }

    @Test(description = "Test case for processAuthenticationResponse() method when Webauthn is enabled", priority = 6)
    public void testProcessAuthenticationResponseWebauthnEnabled() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);
        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(true));

        // Use MockedConstruction for WebAuthnService
        try (MockedConstruction<WebAuthnService> webAuthnServiceMockedConstruction = Mockito.mockConstruction(
                WebAuthnService.class, (mock, context1) -> {
                    doNothing().when(mock).finishAuthentication(anyString(), anyString(), anyString(), anyString());
                })) {
            fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
            Assert.assertEquals(context.getSubject(), authenticatedUser);
            Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
        }
    }

    @Test(description = "Test case for processAuthenticationResponse() method when Webauthn is disabled", priority = 7)
    public void testProcessAuthenticationResponseWebauthnDisabled() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(false));

        u2FServiceMock = Mockito.mockStatic(U2FService.class);
        u2FServiceMock.when(U2FService::getInstance).thenReturn(u2FService);
        authenticateResponseMock = Mockito.mockStatic(AuthenticateResponse.class);
        authenticateResponseMock.when(() -> AuthenticateResponse.fromJson(anyString())).thenReturn(authenticateResponse);

        fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(context.getSubject(), authenticatedUser);
        Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
    }

    @Test(description = "Test case for getContextIdentifier() method", priority = 8)
    public void testGetContextIdentifier() {

        final String sessionDataKey = "654321";
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(sessionDataKey);
        Assert.assertEquals(fidoAuthenticator.getContextIdentifier(httpServletRequest), sessionDataKey);
    }

    @Test(description = "Test case for getName() method", priority = 9)
    public void testGetName() {

        Assert.assertEquals(fidoAuthenticator.getName(), FIDOAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for getFriendlyName() method", priority = 10)
    public void testGetFriendlyName() {

        Assert.assertEquals(fidoAuthenticator.getFriendlyName(),
                AUTHENTICATOR_FRIENDLY_NAME);
    }

    @DataProvider(name = "initiateAuthenticationRequestWebauthnDataProvider")
    public static Object[][] initiateAuthenticationRequestWebauthnDataProvider() {

        return new Object[][]{
                {"1234"}, {null}
        };
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is enabled",
            dataProvider = "initiateAuthenticationRequestWebauthnDataProvider", priority = 11)
    public void testInitiateAuthenticationRequestWebauthnEnabled(String startAuthenticationResponse) throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(true));

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO2_AUTH, "fido2-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        fileBasedConfigurationBuilderMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        urlEncoderMock = Mockito.mockStatic(URLEncoder.class);
        urlEncoderMock.when(() -> URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        // Use MockedConstruction for WebAuthnService
        try (MockedConstruction<WebAuthnService> webAuthnServiceMockedConstruction = Mockito.mockConstruction(
                WebAuthnService.class, (mock, context1) -> {
                    when(mock.startAuthentication(anyString(), anyString(), anyString(), anyString()))
                            .thenReturn(startAuthenticationResponse);
                    when(mock.startUsernamelessAuthentication(anyString())).thenReturn(startAuthenticationResponse);
                })) {
            fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        } catch (Exception e) {
            if (startAuthenticationResponse == null) {
                Assert.assertEquals(e.getClass(), AuthenticationFailedException.class);
            } else {
                Assert.fail("Unexpected exception occurred.");
            }
        }
    }

    @DataProvider(name = "initiateAuthenticationRequestU2FDataProvider")
    public static Object[][] initiateAuthenticationRequestU2FDataProvider() {

        AuthenticateRequestData authenticateRequestData = mock(AuthenticateRequestData.class);
        when(authenticateRequestData.toJson()).thenReturn("1234");

        return new Object[][]{
                {false}, {true}
        };
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is disabled",
            dataProvider = "initiateAuthenticationRequestU2FDataProvider", priority = 12)
    public void testInitiateAuthenticationRequestWebauthnDisabled(boolean isU2FNullResponse)
            throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(false));

        u2FServiceMock = Mockito.mockStatic(U2FService.class);
        u2FServiceMock.when(U2FService::getInstance).thenReturn(u2FService);
        authenticateResponseMock = Mockito.mockStatic(AuthenticateResponse.class);

        if (isU2FNullResponse) {
            when(u2FService.startAuthentication(any())).thenReturn(null);
        } else {
            when(u2FService.startAuthentication(any())).thenReturn(authenticateRequestData);
        }

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO_AUTH, "fido-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        fileBasedConfigurationBuilderMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        urlEncoderMock = Mockito.mockStatic(URLEncoder.class);
        urlEncoderMock.when(() -> URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        try {
            fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        } catch (Exception e) {
            if (isU2FNullResponse) {
                Assert.assertEquals(e.getClass(), AuthenticationFailedException.class);
            } else {
                Assert.fail("Unexpected exception occurred.");
            }
        }
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method", priority = 13)
    public void testRetryAuthenticationEnabled() {

        Assert.assertFalse(fidoAuthenticator.retryAuthenticationEnabled());
    }

    @Test
    public void testGetAuthInitiationData() {

        when(authenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("LOCAL");
        when(authenticationContext.getProperty(anyString())).thenReturn(SAMPLE_TOKEN_CHALLENGE);
        Optional<AuthenticatorData> authenticatorData = fidoAuthenticator.getAuthInitiationData
                (authenticationContext);
        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(), 1);
        Assert.assertEquals(authenticatorDataObj.getI18nKey(), AUTHENTICATOR_FIDO);
        Assert.assertEquals(authenticatorDataObj.getDisplayName(), AUTHENTICATOR_FRIENDLY_NAME);

        Assert.assertNotNull(authenticatorDataObj.getAdditionalData());
        Map<String, String> additionalData = authenticatorDataObj.getAdditionalData()
                .getAdditionalAuthenticationParams();
        Assert.assertTrue(additionalData.containsKey(FIDOAuthenticatorConstants.CHALLENGE_DATA));
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = fidoAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test(description = "Test case for processAuthenticationResponse() method when user account is locked", priority = 14)
    public void testProcessAuthenticationResponseWithLockedUser() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(true));

        when(mockAccountLockService.isAccountLocked(USERNAME, SUPER_TENANT_DOMAIN, USER_STORE_DOMAIN))
                .thenReturn(true);

        // Use MockedConstruction for WebAuthnService
        try (MockedConstruction<WebAuthnService> webAuthnServiceMockedConstruction = Mockito.mockConstruction(
                WebAuthnService.class, (mock, context1) -> {
                    doNothing().when(mock).finishAuthentication(anyString(), anyString(), anyString(), anyString());
                })) {
            fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
            Assert.fail("Expected AuthenticationFailedException was not thrown");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage()
                    .contains(FIDOAuthenticatorConstants.AUTHENTICATION_FAILED_ACCOUNT_LOCKED_ERROR_MESSAGE));
        }
    }

    @Test(description = "Test case for processAuthenticationResponse() method when account lock check throws exception", priority = 15)
    public void testProcessAuthenticationResponseWithAccountLockException() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        identityUtilMock.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        identityUtilMock.when(() -> IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED))
                .thenReturn(String.valueOf(true));

        when(mockAccountLockService.isAccountLocked(USERNAME, SUPER_TENANT_DOMAIN, USER_STORE_DOMAIN))
                .thenThrow(new AccountLockServiceException("Account lock service error"));

        // Use MockedConstruction for WebAuthnService
        try (MockedConstruction<WebAuthnService> webAuthnServiceMockedConstruction = Mockito.mockConstruction(
                WebAuthnService.class, (mock, context1) -> {
                    doNothing().when(mock).finishAuthentication(anyString(), anyString(), anyString(), anyString());
                })) {
            fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
            Assert.fail("Expected AuthenticationFailedException was not thrown");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Error occurred while checking account lock status for user"));
        }
    }
}
