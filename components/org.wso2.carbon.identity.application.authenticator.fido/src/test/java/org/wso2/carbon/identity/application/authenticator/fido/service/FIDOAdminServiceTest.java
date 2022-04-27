/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.fido.service;

import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;

import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

import java.nio.file.Paths;
import java.util.ArrayList;

import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@PrepareForTest({U2FService.class, CarbonContext.class, PrivilegedCarbonContext.class, FIDOUtil.class,
        RegisterResponse.class})
public class FIDOAdminServiceTest {

    private final String USER_STORE_DOMAIN = "PRIMARY";
    private final String USERNAME = "admin";
    private final String APP_ID = "https://localhost:9443";
    private FIDOAdminService fidoAdminService;
    private CarbonContext carbonContext;

    @Mock
    private U2FService u2FService;
    @Mock
    private RegisterRequestData registerRequestData;
    @Mock
    private RegisterResponse registerResponse;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        mockStatic(U2FService.class);
        when(U2FService.getInstance()).thenReturn(u2FService);
        mockCarbonContext();
        mockStatic(FIDOUtil.class);
        when(FIDOUtil.getDomainName(anyString())).thenReturn(USER_STORE_DOMAIN);
        when(FIDOUtil.getUsernameWithoutDomain(anyString())).thenReturn(USERNAME);
        fidoAdminService = new FIDOAdminService();
    }

    @Test(description = "Test case for startRegistration() method")
    public void testStartRegistration() throws FIDOAuthenticatorServerException, FIDOAuthenticatorClientException {

        when(u2FService.startRegistration(any())).thenReturn(registerRequestData);
        when(registerRequestData.toJson()).thenReturn("1234");
        Assert.assertEquals(fidoAdminService.startRegistration(APP_ID), "1234");
    }

    @Test(description = "Test case for finishRegistration() method")
    public void testFinishRegistration() throws FIDOAuthenticatorClientException {

        String response = "testResponse";
        mockStatic(RegisterResponse.class);
        when(RegisterResponse.fromJson(anyString())).thenReturn(registerResponse);
        fidoAdminService.finishRegistration(response);
    }

    @Test(description = "Test case for removeAllRegistrations() method")
    public void testRemoveAllRegistrations() throws FIDOAuthenticatorClientException {

        fidoAdminService.removeAllRegistrations();
    }

    @Test(description = "Test case for removeRegistration() method")
    public void testRemoveRegistration() throws FIDOAuthenticatorClientException {

        fidoAdminService.removeRegistration("deviceRemarks");
    }

    @Test(description = "Test case for isDeviceRegistered() method when there's a registered device")
    public void testIsDeviceRegisteredForRegisteredUser() throws FIDOAuthenticatorClientException,
            FIDOAuthenticatorServerException {

        when(u2FService.isDeviceRegistered(any())).thenReturn(true);
        Assert.assertTrue(fidoAdminService.isDeviceRegistered());
    }

    @Test(description = "Test case for isDeviceRegistered() method when there's no registered device")
    public void testIsDeviceRegisteredForNonRegisteredUser() throws FIDOAuthenticatorClientException,
            FIDOAuthenticatorServerException {

        when(u2FService.isDeviceRegistered(any())).thenReturn(false);
        Assert.assertFalse(fidoAdminService.isDeviceRegistered());
    }

    @Test(description = "Test case for getDeviceMetadataList() when devices are there")
    public void testGetDeviceMetadataListWhenDevicesPresent() throws FIDOAuthenticatorClientException,
            FIDOAuthenticatorServerException {

        ArrayList<String> deviceList = new ArrayList<>();
        deviceList.add("device1");
        deviceList.add("device2");
        when(u2FService.getDeviceMetadata(any())).thenReturn(deviceList);
        String[] returnedDeviceList = fidoAdminService.getDeviceMetadataList();
        Assert.assertEquals(returnedDeviceList, deviceList.toArray(new String[0]));
    }

    @Test(description = "Test case for getDeviceMetadataList() when devices are not there")
    public void testGetDeviceMetadataListWhenDevicesNotPresent() throws FIDOAuthenticatorClientException,
            FIDOAuthenticatorServerException {

        ArrayList<String> deviceList = new ArrayList<>();
        when(u2FService.getDeviceMetadata(any())).thenReturn(deviceList);
        String[] returnedDeviceList = fidoAdminService.getDeviceMetadataList();
        Assert.assertEquals(returnedDeviceList.length, 0);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    private void mockCarbonContext() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());

        mockStatic(PrivilegedCarbonContext.class);
        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        when(privilegedCarbonContext.getTenantId()).thenReturn(SUPER_TENANT_ID);
        when(privilegedCarbonContext.getUsername()).thenReturn(USERNAME);

        mockStatic(CarbonContext.class);
        carbonContext = mock(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
    }
}
