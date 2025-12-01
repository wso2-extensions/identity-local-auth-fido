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

package org.wso2.carbon.identity.application.authenticator.fido.u2f;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.NoEligableDevicesException;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.fido.dao.DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class U2FServiceTest {

    private final String APP_ID = "https://localhost:9443";
    private final String USERNAME = "admin";
    private final String USER_STORE_DOMAIN = "PRIMARY";
    private U2FService u2FService;

    @Mock
    private DeviceStoreDAO deviceStoreDAO;
    @Mock
    private U2F u2F;
    @Mock
    private AuthenticateResponse authenticateResponse;
    @Mock
    private RegisterResponse registerResponse;

    private MockedStatic<DeviceStoreDAO> deviceStoreDAOMock;
    private MockedStatic<DeviceRegistration> deviceRegistrationMock;
    private MockedStatic<AuthenticateRequestData> authenticateRequestDataMock;
    private MockedStatic<RegisterRequestData> registerRequestDataMock;
    private MockedStatic<Timestamp> timestampMock;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        // Intercept U2F constructor and inject our mock into the singleton
        try (MockedConstruction<U2F> ignored = Mockito.mockConstruction(U2F.class)) {
            u2FService = U2FService.getInstance();
        }
        Field u2FField = U2FService.class.getDeclaredField("u2f");
        u2FField.setAccessible(true);
        u2FField.set(u2FService, u2F);

        deviceStoreDAOMock = Mockito.mockStatic(DeviceStoreDAO.class);
        deviceRegistrationMock = Mockito.mockStatic(DeviceRegistration.class);
        authenticateRequestDataMock = Mockito.mockStatic(AuthenticateRequestData.class);
        registerRequestDataMock = Mockito.mockStatic(RegisterRequestData.class);
        timestampMock = Mockito.mockStatic(Timestamp.class);
    }

    @AfterMethod
    public void cleanUp() throws NoSuchFieldException, IllegalAccessException {

        if (deviceStoreDAOMock != null) {
            deviceStoreDAOMock.close();
        }
        if (deviceRegistrationMock != null) {
            deviceRegistrationMock.close();
        }
        if (authenticateRequestDataMock != null) {
            authenticateRequestDataMock.close();
        }
        if (registerRequestDataMock != null) {
            registerRequestDataMock.close();
        }
        if (timestampMock != null) {
            timestampMock.close();
        }

        Field instance = U2FService.class.getDeclaredField("u2FService");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @Test(description = "Test case for startAuthentication() method", priority = 1)
    public void testStartAuthentication() throws AuthenticationFailedException, NoEligableDevicesException,
            FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        AuthenticateRequestData authenticateRequestData = mock(AuthenticateRequestData.class);
        when(authenticateRequestData.getRequestId()).thenReturn("1234");
        when(authenticateRequestData.toJson()).thenReturn("JSONString");
        DeviceRegistration deviceRegistration = mock(DeviceRegistration.class);

        Multimap<String, String> devices = ArrayListMultimap.create();
        devices.put("keyHandle1", "deviceData1");
        devices.put("keyHandle2", "deviceData2");
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());

        deviceRegistrationMock.when(() -> DeviceRegistration.fromJson(anyString())).thenReturn(deviceRegistration);
        when(u2F.startAuthentication(anyString(), any())).thenReturn(authenticateRequestData);
        Assert.assertEquals(u2FService.startAuthentication(fidoUser), authenticateRequestData);
    }

    @Test(description = "Test case for startAuthentication() method when no registered devices found", priority = 2)
    public void testStartAuthenticationWhenNoRegisteredDevices() throws AuthenticationFailedException,
            NoEligableDevicesException, FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        AuthenticateRequestData authenticateRequestData = mock(AuthenticateRequestData.class);
        when(authenticateRequestData.getRequestId()).thenReturn("1234");
        when(authenticateRequestData.toJson()).thenReturn("JSONString");
        DeviceRegistration deviceRegistration = mock(DeviceRegistration.class);

        Multimap<String, String> devices = ArrayListMultimap.create();
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());

        deviceRegistrationMock.when(() -> DeviceRegistration.fromJson(anyString())).thenReturn(deviceRegistration);
        Assert.assertNull(u2FService.startAuthentication(fidoUser));
    }

    @Test(description = "Test case for finishAuthentication() method", priority = 3)
    public void testFinishAuthentication() throws DeviceCompromisedException, FIDOAuthenticatorServerException,
            AuthenticationFailedException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, authenticateResponse);
        AuthenticateRequestData authenticateRequestData = mock(AuthenticateRequestData.class);
        DeviceRegistration deviceRegistration = mock(DeviceRegistration.class);

        Multimap<String, String> devices = ArrayListMultimap.create();
        devices.put("keyHandle1", "deviceData1");
        devices.put("keyHandle2", "deviceData2");
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());

        authenticateRequestDataMock.when(() -> AuthenticateRequestData.fromJson(anyString()))
                .thenReturn(authenticateRequestData);
        when(u2F.finishAuthentication(any(), any(), any())).thenReturn(deviceRegistration);
        u2FService.finishAuthentication(fidoUser);
    }

    @Test(description = "Test case for startRegistration() method", priority = 4)
    public void testStartRegistration() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        RegisterRequestData registerRequestData = mock(RegisterRequestData.class);
        when(registerRequestData.getRequestId()).thenReturn("1234");
        when(registerRequestData.toJson()).thenReturn("JSONString");

        Multimap<String, String> devices = ArrayListMultimap.create();
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());

        when(u2F.startRegistration(anyString(), any())).thenReturn(registerRequestData);
        Assert.assertEquals(u2FService.startRegistration(fidoUser), registerRequestData);
    }

    @Test(description = "Test case for finishRegistration() method", priority = 5)
    public void testFinishRegistration() throws FIDOAuthenticatorServerException, NoSuchFieldException,
            IllegalAccessException {

        when(registerResponse.getRequestId()).thenReturn("1234");
        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, registerResponse);
        RegisterRequestData registerRequestData = mock(RegisterRequestData.class);
        registerRequestDataMock.when(() -> RegisterRequestData.fromJson(anyString()))
                .thenReturn(registerRequestData);

        Map<String, String> requestStorageMap = new HashMap<String, String>();
        requestStorageMap.put("1234", "JSONString");
        Field requestStorage = U2FService.class.getDeclaredField("requestStorage");
        requestStorage.setAccessible(true);
        requestStorage.set(requestStorage, requestStorageMap);

        DeviceRegistration deviceRegistration = mock(DeviceRegistration.class);
        when(u2F.finishRegistration(any(), any())).thenReturn(deviceRegistration);
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        u2FService.finishRegistration(fidoUser);
        Assert.assertEquals(fidoUser.getDeviceRegistration(), deviceRegistration);
    }

    @Test(description = "Test case for isDeviceRegistered() method", priority = 6)
    public void testIsDeviceRegistered() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        Multimap<String, String> devices = ArrayListMultimap.create();
        devices.put("keyHandle1", "deviceData1");
        devices.put("keyHandle2", "deviceData2");
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());
        Assert.assertTrue(u2FService.isDeviceRegistered(fidoUser));
    }

    @Test(description = "Test case for isDeviceRegistered() method when no registered devices", priority = 7)
    public void testIsDeviceRegisteredWhenNoRegisteredDevices() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        Multimap<String, String> devices = ArrayListMultimap.create();
        when(deviceStoreDAO.getDeviceRegistration(anyString(), anyString(), anyString())).thenReturn(devices.values());
        Assert.assertFalse(u2FService.isDeviceRegistered(fidoUser));
    }

    @Test(description = "Test case for getDeviceMetadata() method", priority = 8)
    public void testGetDeviceMetadata() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        ArrayList<String> deviceMetadata = new ArrayList<>();
        deviceMetadata.add("deviceMetadata1");
        deviceMetadata.add("deviceMetadata2");
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        when(deviceStoreDAO.getDeviceMetadata(anyString(), anyString(), anyString())).thenReturn(deviceMetadata);
        Assert.assertEquals(u2FService.getDeviceMetadata(fidoUser), deviceMetadata);
    }

    @Test(description = "Test case for removeAllRegistrations() method", priority = 9)
    public void testRemoveAllRegistrations() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        u2FService.removeAllRegistrations(fidoUser);
    }

    @Test(description = "Test case for removeRegistration() method", priority = 10)
    public void testRemoveRegistration() throws FIDOAuthenticatorServerException {

        FIDOUser fidoUser = new FIDOUser(USERNAME, SUPER_TENANT_DOMAIN_NAME, USER_STORE_DOMAIN, APP_ID);
        deviceStoreDAOMock.when(DeviceStoreDAO::getInstance).thenReturn(deviceStoreDAO);
        timestampMock.when(() -> Timestamp.valueOf(anyString())).thenReturn(new Timestamp(new Date().getTime()));
        u2FService.removeRegistration(fidoUser, "deviceRemarks");
    }
}
