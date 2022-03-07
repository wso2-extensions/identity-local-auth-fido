package org.wso2.carbon.identity.application.authenticator.fido2;

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;

import static org.mockito.MockitoAnnotations.initMocks;

public class WebAuthnServiceTest {

    @Mock
    private WebAuthnService webAuthnService;

    @BeforeMethod
    public void setUp() {
        webAuthnService = new WebAuthnService();
        initMocks(this);
        //
    }

    @Test
    public void testStartFIDO2Registration() {

    }

}
