package org.wso2.carbon.identity.application.authenticator.fido;

import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PrepareForTest({FIDOAuthenticator.class, IdentityUtil.class, MultitenantUtils.class, IdentityTenantUtil.class,
    U2FService.class, AuthenticateResponse.class, ConfigurationFacade.class, FileBasedConfigurationBuilder.class,
    URLEncoder.class, ServiceURLBuilder.class})
public class FIDOAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private final String USERNAME = "admin";
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

    @BeforeMethod
    public void setUp() {
        fidoAuthenticator = FIDOAuthenticator.getInstance();
        initMocks(this);
        mockStatic(FIDOAuthenticator.class);
        mockStatic(IdentityUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
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
                PowerMockito.when(serviceURL.getAbsolutePublicURL()).thenReturn("http://localhost:9443" + path);
                PowerMockito.when(serviceURL.getRelativePublicURL()).thenReturn(path);
                PowerMockito.when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        PowerMockito.when(ServiceURLBuilder.create()).thenReturn(builder);
    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandle() {

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        Assert.assertTrue(fidoAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() {

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
        Assert.assertFalse(fidoAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for successful logout request with valid token response.")
    public void testProcessLogoutRequestWithValidTokenResponse() throws Exception {

        when(authenticationContext.isLogoutRequest()).thenReturn(true);
        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        AuthenticatorFlowStatus status = fidoAuthenticator.process(
                httpServletRequest, httpServletResponse, authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for successful logout request with null token response.")
    public void testProcessLogoutRequestWithNullTokenResponse() throws Exception {

        when(authenticationContext.isLogoutRequest()).thenReturn(true);
        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
        AuthenticatorFlowStatus status = fidoAuthenticator.process(
                httpServletRequest, httpServletResponse, authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for usernameless processAuthenticationResponse() method when Webauthn is enabled")
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

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(true));
        when(webAuthnService.finishUsernamelessAuthentication(anyString())).thenReturn(authenticatedUser);
        whenNew(WebAuthnService.class).withNoArguments().thenReturn(webAuthnService);
        fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(context.getSubject(), authenticatedUser);
        Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
    }

    @Test(description = "Test case for processAuthenticationResponse() method when Webauthn is enabled")
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

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(true));
        whenNew(WebAuthnService.class).withNoArguments().thenReturn(webAuthnService);
        fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(context.getSubject(), authenticatedUser);
        Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
    }

    @Test(description = "Test case for processAuthenticationResponse() method when Webauthn is disabled")
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

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(false));

        mockStatic(U2FService.class);
        when(U2FService.getInstance()).thenReturn(u2FService);
        mockStatic(AuthenticateResponse.class);
        when(AuthenticateResponse.fromJson(anyString())).thenReturn(authenticateResponse);

        fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(context.getSubject(), authenticatedUser);
        Assert.assertEquals(context.getLastAuthenticatedUser(), authenticatedUser);
    }

    @Test(description = "Test case for getContextIdentifier() method")
    public void testGetContextIdentifier() {

        final String sessionDataKey = "654321";
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(sessionDataKey);
        Assert.assertEquals(fidoAuthenticator.getContextIdentifier(httpServletRequest), sessionDataKey);
    }

    @Test(description = "Test case for getName() method")
    public void testGetName() {

        Assert.assertEquals(fidoAuthenticator.getName(), FIDOAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for getFriendlyName() method")
    public void testGetFriendlyName() {

        Assert.assertEquals(fidoAuthenticator.getFriendlyName(), FIDOAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is enabled and returns " +
            "non null response")
    public void testInitiateAuthenticationRequestWebauthnEnabled() throws Exception {

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

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(true));
        whenNew(WebAuthnService.class).withNoArguments().thenReturn(webAuthnService);
        when(webAuthnService.startAuthentication(anyString(), anyString(), anyString(), anyString())).thenReturn(
                "1234");

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO2_AUTH, "fido2-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockStatic(URLEncoder.class);
        when(URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is enabled and returns " +
            "null response")
    public void testInitiateAuthenticationRequestWebauthnEnabledNullResponse() throws Exception {

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

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(true));
        whenNew(WebAuthnService.class).withNoArguments().thenReturn(webAuthnService);
        when(webAuthnService.startAuthentication(anyString(), anyString(), anyString(), anyString())).thenReturn(null);
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO2_AUTH, "fido2-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockStatic(URLEncoder.class);
        when(URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is disabled and returns " +
            "non null response")
    public void testInitiateAuthenticationRequestWebauthnDisabled() throws Exception {

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

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(false));

        mockStatic(U2FService.class);
        when(U2FService.getInstance()).thenReturn(u2FService);
        mockStatic(AuthenticateResponse.class);
        when(u2FService.startAuthentication(any())).thenReturn(authenticateRequestData);
        when(authenticateRequestData.toJson()).thenReturn("1234");
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO_AUTH, "fido-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockStatic(URLEncoder.class);
        when(URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when Webauthn is disabled and returns " +
            "null response")
    public void testInitiateAuthenticationRequestWebauthnDisabledNullResponse() throws Exception {

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

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED)).thenReturn(String.valueOf(false));

        mockStatic(U2FService.class);
        when(U2FService.getInstance()).thenReturn(u2FService);
        mockStatic(AuthenticateResponse.class);
        when(u2FService.startAuthentication(any())).thenReturn(null);
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FIDOAuthenticatorConstants.APP_ID, "https://localhost:9443");
        parameterMap.put(FIDOAuthenticatorConstants.FIDO_AUTH, "fido-auth");
        authenticatorConfig.setParameterMap(parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockStatic(URLEncoder.class);
        when(URLEncoder.encode(anyString(), anyString())).thenReturn("encodedUrl");
        mockServiceURLBuilder();

        fidoAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method")
    public void testRetryAuthenticationEnabled() {

        Assert.assertFalse(fidoAuthenticator.retryAuthenticationEnabled());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }
}
