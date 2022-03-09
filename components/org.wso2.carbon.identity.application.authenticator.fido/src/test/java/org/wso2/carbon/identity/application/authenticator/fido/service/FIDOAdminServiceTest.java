package org.wso2.carbon.identity.application.authenticator.fido.service;

import com.yubico.u2f.data.messages.RegisterRequestData;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;

import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({U2FService.class, CarbonContext.class, FIDOUtil.class})
public class FIDOAdminServiceTest {

    private final String LOGGED_IN_USER = "PRIMARY/admin";
    private final String USER_STORE_DOMAIN = "PRIMARY";
    private final String SUPER_TENANT_DOMAIN = "carbon.super";
    private final String USERNAME = "admin";
    private final String APP_ID = "https://localhost:9443";
    private FIDOAdminService fidoAdminService;

    @Mock
    private U2FService u2FService;
    @Mock
    private CarbonContext carbonContext;
    @Mock
    private RegisterRequestData registerRequestData;

    @BeforeMethod
    public void setUp() {

        fidoAdminService = new FIDOAdminService();
        initMocks(this);
        mockStatic(U2FService.class);
        when(U2FService.getInstance()).thenReturn(u2FService);
        mockStatic(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn(LOGGED_IN_USER);
        mockStatic(FIDOUtil.class);
        when(FIDOUtil.getDomainName(anyString())).thenReturn(USER_STORE_DOMAIN);
        when(FIDOUtil.getUsernameWithoutDomain(anyString())).thenReturn(USERNAME);
        when(carbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN);
    }

    @Test(description = "Test case for startRegistration() method")
    public void testStartRegistration() throws FIDOAuthenticatorServerException, FIDOAuthenticatorClientException {

        when(u2FService.startRegistration(any())).thenReturn(registerRequestData);
        when(registerRequestData.toJson()).thenReturn("1234");
        Assert.assertEquals(fidoAdminService.startRegistration(APP_ID), "1234");
    }

//    @Test(description = "Test case for finishRegistration() method")
//    public void testFinishRegistration() {
//
//        //
//    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }
}
