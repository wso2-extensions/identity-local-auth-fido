package org.wso2.carbon.identity.application.authenticator.fido;

import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({FIDOAuthenticator.class, IdentityUtil.class, MultitenantUtils.class, IdentityTenantUtil.class,
        FrameworkUtils.class})
public class FIDOAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";

    private FIDOAuthenticator fidoAuthenticator;

    @Mock
    private FIDOAuthenticator mockedFidoAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private SequenceConfig sequenceConfig;

    @BeforeMethod
    public void setUp() {
        fidoAuthenticator = FIDOAuthenticator.getInstance();
        initMocks(this);
        mockStatic(FIDOAuthenticator.class);
        mockStatic(IdentityUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(FrameworkUtils.class);
    }

//    @Test(description = "Test case for canHandle() method true case.")
//    public void testCanHandle() {
//
//        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
//        Assert.assertTrue(fidoAuthenticator.canHandle(httpServletRequest));
//    }
//
//    @Test(description = "Test case for canHandle() method false case.")
//    public void testCanHandleFalse() {
//
//        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
//        Assert.assertFalse(fidoAuthenticator.canHandle(httpServletRequest));
//    }
//
//    @Test(description = "Test case for successful logout request with valid token response.")
//    public void testProcessLogoutRequestWithValidTokenResponse() throws Exception {
//
//        when(context.isLogoutRequest()).thenReturn(true);
//        when(httpServletRequest.getParameter("tokenResponse")).thenReturn("123456");
//        AuthenticatorFlowStatus status = fidoAuthenticator.process(httpServletRequest, httpServletResponse, context);
//        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
//    }
//
//    @Test(description = "Test case for successful logout request with null token response.")
//    public void testProcessLogoutRequestWithNullTokenResponse() throws Exception {
//
//        when(context.isLogoutRequest()).thenReturn(true);
//        when(httpServletRequest.getParameter("tokenResponse")).thenReturn(null);
//        AuthenticatorFlowStatus status = fidoAuthenticator.process(httpServletRequest, httpServletResponse, context);
//        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
//    }

//    @Test(description = "Test case for process() method")
//    public void testProcess() {
//
//        AuthenticationContext authenticationContext = new AuthenticationContext();
//        String username = "admin";
//        authenticationContext.setProperty("username", username);
//
//    }

    @Test(description = "Test case for processAuthenticationResponse() method")
    public void testProcessAuthenticationResponse() throws AuthenticationFailedException {

        setupSequenceConfig();
        fidoAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    private void setupSequenceConfig() {

        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setApplicationAuthenticator(fidoAuthenticator);
        authenticatorList.add(authenticatorConfig);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatorList(authenticatorList);

        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);

        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);

        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);

        String username = "admin";
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);

        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
    }

}
