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

package org.wso2.carbon.identity.application.authenticator.fido2.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.InternetDomainName;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessValidator;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2Cache;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheEntry;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheKey;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionRequestWrapper;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.RegistrationResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.MetadataService;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anySet;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@PrepareForTest({FIDO2DeviceStoreDAO.class, IdentityUtil.class, JacksonCodecs.class, IdentityConfigParser.class,
        UserCoreUtil.class, CarbonContext.class, PrivilegedCarbonContext.class, User.class, RelyingParty.class,
        PublicKeyCredentialCreationOptions.class, StartRegistrationOptions.class, FIDO2Cache.class,
        FIDO2CacheEntry.class, IdentityTenantUtil.class, FIDO2AuthenticatorServiceComponent.class,
        InternetDomainName.class, FIDO2CredentialRegistration.class, PublicKeyCredentialCreationOptions.class,
        FIDO2AuthenticatorServiceDataHolder.class, ConfigurationManager.class, FinishRegistrationOptions.class,
        RegistrationResult.class, RegisteredCredential.class, PublicKeyCredentialDescriptor.class, UserIdentity.class,
        AuthenticatorSelectionCriteria.class, RelyingPartyIdentity.class, WebAuthnService.class, WebAuthnManager.class,
        RegistrationData.class, AssertionRequest.class, FIDO2CredentialRegistration.class, FIDOUtil.class,
        StartAssertionOptions.class, AssertionResult.class})
public class WebAuthnServiceTest {

    private final String ORIGIN = "https://localhost:9443";
    private final String USERNAME = "admin";
    private final String TENANT_DOMAIN = "carbon.super";
    private final String TENANT_QUALIFIED_USERNAME = "admin@carbon.super";
    private final String DISPLAY_NAME = "Administrator";
    private final String FIRST_NAME = "admin";
    private final String LAST_NAME = "admin";
    private final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String DISPLAY_NAME_CLAIM_URL = "http://wso2.org/claims/displayName";
    private static final String FIRST_NAME_CLAIM_URL = "http://wso2.org/claims/givenname";
    private static final String LAST_NAME_CLAIM_URL = "http://wso2.org/claims/lastname";
    private static final String CREDENTIAL_ID = "ATfjfbakUOSN_bz0bFThKAL9nA8FtZVKsKLZr1-ab6kGSiG36eIU8pHnG38sbgmg3U5" +
            "ad7QFULle0ee0vn2rwah74_IuSjsWL_3LNgk8emvOcBppGO1dqB6tQsllRQg";

    private WebAuthnService webAuthnService;
    private final Map<String, Object> identityConfig = new HashMap<>();
    private final ArrayList<String> trustedOrigins = new ArrayList<>();
    private User user;

    private String finishRegistrationResponseString;
    private RegistrationResponse finishRegistrationResponse;
    private String finishAuthenticationResponseString;
    private AssertionResponse finishAuthenticationResponse;
    private String finishUsernamelessAuthenticationResponseString;
    private AssertionResponse finishUsernamelessAuthenticationResponse;

    @Mock
    private FIDO2DeviceStoreDAO userStorageMock;
    @Mock
    private FIDO2DeviceStoreDAO fido2DeviceStoreDAO;
    @Mock
    private IdentityConfigParser identityConfigParser;
    @Mock
    private ObjectMapper objectMapperMock;
    @Mock
    private RelyingParty relyingParty;
    @Mock
    private RelyingParty.RelyingPartyBuilder relyingPartyBuilder;
    @Mock
    private RelyingParty.RelyingPartyBuilder.MandatoryStages mandatoryStages;
    @Mock
    private RelyingParty.RelyingPartyBuilder.MandatoryStages.Step2 step2;
    @Mock
    private FIDO2Cache fido2Cache;
    @Mock
    private FIDO2CacheEntry fido2CacheEntry;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private InternetDomainName internetDomainName;
    @Mock
    private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
    @Mock
    private FIDO2AuthenticatorServiceDataHolder fido2AuthenticatorServiceDataHolder;
    @Mock
    private ConfigurationManager configurationManager;
    @Mock
    private RegistrationResult registrationResult;
    @Mock
    private WebAuthnManager webAuthnManager;
    @Mock
    private RegistrationData registrationData;
    @Mock
    private FIDO2CredentialRegistration fido2CredentialRegistration;
    @Mock
    private AssertionRequest assertionRequest;
    @Mock
    private FIDOUtil fidoUtil;
    @Mock
    private AssertionResult assertionResult;

    @BeforeMethod
    public void setUp() throws UserStoreException, IOException, FIDO2AuthenticatorServerException {

        prepareResources();
        initMocks(this);
        mockStatic(FIDO2DeviceStoreDAO.class);
        when(FIDO2DeviceStoreDAO.getInstance()).thenReturn(userStorageMock);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty("FIDO.UserResponseTimeout")).thenReturn("300");
        mockStatic(JacksonCodecs.class);
        when(JacksonCodecs.json()).thenReturn(objectMapperMock);
        webAuthnService = new WebAuthnService();

        when(FIDO2DeviceStoreDAO.getInstance()).thenReturn(fido2DeviceStoreDAO);
        trustedOrigins.add(ORIGIN);
        identityConfig.put(FIDO2AuthenticatorConstants.TRUSTED_ORIGINS, trustedOrigins);
        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(identityConfig);
        when(IdentityUtil.fillURLPlaceholders(anyString())).thenReturn(ORIGIN);

        mockCarbonContext();
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn(TENANT_QUALIFIED_USERNAME);

        mockStatic(User.class);
        user = new User();
        user.setUserName(TENANT_QUALIFIED_USERNAME);
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        when(User.getUserFromUserName(TENANT_QUALIFIED_USERNAME)).thenReturn(user);
        when(User.getUserFromUserName(USERNAME)).thenReturn(user);

        mockStatic(RelyingParty.class);
        mockStatic(RelyingParty.RelyingPartyBuilder.class);
        when(RelyingParty.builder()).thenReturn(mandatoryStages);
        when(mandatoryStages.identity(any())).thenReturn(step2);
        when(step2.credentialRepository(any())).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.origins(anySet())).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.attestationConveyancePreference(AttestationConveyancePreference.DIRECT))
                .thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.preferredPubkeyParams(anyList())).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.build()).thenReturn(relyingParty);

        mockStatic(FIDO2Cache.class);
        when(FIDO2Cache.getInstance()).thenReturn(fido2Cache);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN_NAME)).thenReturn(SUPER_TENANT_ID);
        mockStatic(FIDO2AuthenticatorServiceComponent.class);
        when(FIDO2AuthenticatorServiceComponent.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValue(TENANT_QUALIFIED_USERNAME, DISPLAY_NAME_CLAIM_URL, null))
                .thenReturn(DISPLAY_NAME);
        when(userStoreManager.getUserClaimValue(TENANT_QUALIFIED_USERNAME, FIRST_NAME_CLAIM_URL, null))
                .thenReturn(FIRST_NAME);
        when(userStoreManager.getUserClaimValue(TENANT_QUALIFIED_USERNAME, LAST_NAME_CLAIM_URL, null))
                .thenReturn(LAST_NAME);

        mockStatic(InternetDomainName.class);
        when(InternetDomainName.from(anyString())).thenReturn(internetDomainName);
        when(internetDomainName.hasPublicSuffix()).thenReturn(false);

        mockStatic(FIDO2AuthenticatorServiceDataHolder.class);
        when(FIDO2AuthenticatorServiceDataHolder.getInstance()).thenReturn(fido2AuthenticatorServiceDataHolder);
        when(fido2AuthenticatorServiceDataHolder.getConfigurationManager()).thenReturn(configurationManager);

        List<FIDO2CredentialRegistration> credentialRegistrations = new ArrayList<>();
        credentialRegistrations.add(fido2CredentialRegistration);
        when(userStorageMock.getFIDO2RegistrationsByUsername(anyString())).thenReturn(credentialRegistrations);
        FIDO2CredentialRegistration fido2CredentialRegistration = mock(FIDO2CredentialRegistration.class);
        when(userStorageMock.getFIDO2RegistrationByUsernameAndCredentialId(anyString(), any(ByteArray.class)))
                .thenReturn(Optional.of(fido2CredentialRegistration));

        mockStatic(FIDOUtil.class);
    }

    @Test(description = "Test case for startFIDO2Registration() method", priority = 1)
    public void testStartFIDO2Registration() throws JsonProcessingException, FIDO2AuthenticatorClientException {

        mockStatic(StartRegistrationOptions.class);
        StartRegistrationOptions startRegistrationOptions = mock(StartRegistrationOptions.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder startRegistrationOptionsBuilder =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages mandatoryStages1 =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages.class);
        when(StartRegistrationOptions.builder()).thenReturn(mandatoryStages1);
        when(fido2DeviceStoreDAO.getUserHandleForUsername(anyString()))
                .thenReturn(Optional.ofNullable(null));
        when(mandatoryStages1.user(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.timeout(anyLong())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.authenticatorSelection(any(AuthenticatorSelectionCriteria.class)))
                .thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.extensions(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.build()).thenReturn(startRegistrationOptions);

        PublicKeyCredentialCreationOptions credentialCreationOptions = mock(PublicKeyCredentialCreationOptions.class);
        when(relyingParty.startRegistration(any())).thenReturn(credentialCreationOptions);
        when(objectMapperMock.writeValueAsString(any())).thenReturn("dummyValueAsString");

        Either<String, FIDO2RegistrationRequest> result = webAuthnService.startFIDO2Registration(ORIGIN);
        Assert.assertTrue(result.isRight());
    }

    @Test(description = "Test case for startFIDO2UsernamelessRegistration() method", priority = 2)
    public void testStartFIDO2UsernamelessRegistration() throws JsonProcessingException,
            FIDO2AuthenticatorClientException {

        mockStatic(StartRegistrationOptions.class);
        StartRegistrationOptions startRegistrationOptions = mock(StartRegistrationOptions.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder startRegistrationOptionsBuilder =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages mandatoryStages1 =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages.class);
        when(StartRegistrationOptions.builder()).thenReturn(mandatoryStages1);
        when(fido2DeviceStoreDAO.getUserHandleForUsername(anyString()))
                .thenReturn(Optional.ofNullable(null));
        when(mandatoryStages1.user(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.timeout(anyLong())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.authenticatorSelection(any(AuthenticatorSelectionCriteria.class)))
                .thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.extensions(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.build()).thenReturn(startRegistrationOptions);

        PublicKeyCredentialCreationOptions credentialCreationOptions = mock(PublicKeyCredentialCreationOptions.class);
        when(relyingParty.startRegistration(any())).thenReturn(credentialCreationOptions);
        when(objectMapperMock.writeValueAsString(any())).thenReturn("dummyValueAsString");

        Either<String, FIDO2RegistrationRequest> result = webAuthnService.startFIDO2UsernamelessRegistration(ORIGIN);
        Assert.assertTrue(result.isRight());
    }

    @DataProvider(name = "finishFIDO2RegistrationDataProvider")
    public static Object[][] finishFIDO2RegistrationDataProvider() {

        return new Object[][] {
                {"false", "false", false},
                {"false", "false", true},
                {"true", "false", false},
                {"true", "true", false},
                {"true", "false", true},
                {"true", "true", true},
                {"false", "true", false}
        };
    }

    @Test(description = "Test case for finishFIDO2Registration() method",
            dataProvider = "finishFIDO2RegistrationDataProvider", priority = 3)
    public void testFinishFIDO2Registration(
            String attestationValidationEnabled, String mdsValidationEnabled, boolean requireResidentKey)
            throws Exception {

        when(objectMapperMock.readValue(finishRegistrationResponseString, RegistrationResponse.class))
                .thenReturn(finishRegistrationResponse);
        when(fido2DeviceStoreDAO.getFIDO2RegistrationByUsernameAndCredentialId(anyString(), any(ByteArray.class)))
                .thenReturn(Optional.ofNullable(null));
        when(fido2Cache.getValueFromCacheByRequestId(any(FIDO2CacheKey.class))).thenReturn(fido2CacheEntry);
        when(fido2CacheEntry.getPublicKeyCredentialCreationOptions())
                .thenReturn("publicKeyCredentialCreationOptions");
        when(objectMapperMock.readValue("publicKeyCredentialCreationOptions",
                PublicKeyCredentialCreationOptions.class)).thenReturn(publicKeyCredentialCreationOptions);
        when(fido2CacheEntry.getOrigin()).thenReturn(new URL(ORIGIN));

        when(configurationManager.getAttribute(FIDO_CONFIG_RESOURCE_TYPE_NAME, FIDO2_CONFIG_RESOURCE_NAME,
                FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME)).thenReturn(
                        new Attribute(FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME, attestationValidationEnabled)
        );
        when(configurationManager.getAttribute(FIDO_CONFIG_RESOURCE_TYPE_NAME, FIDO2_CONFIG_RESOURCE_NAME,
                FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME)).thenReturn(
                new Attribute(FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME, mdsValidationEnabled)
        );

        if (Boolean.parseBoolean(attestationValidationEnabled)) {
            when(relyingParty.getOrigins()).thenReturn(new HashSet<String>(Arrays.asList(ORIGIN)));

            List<PublicKeyCredentialParameters> preferredPublicKeyCredentialParameters = Collections.unmodifiableList(
                    Arrays.asList(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.EdDSA,
                            PublicKeyCredentialParameters.RS1, PublicKeyCredentialParameters.RS256)
            );
            when(relyingParty.getPreferredPubkeyParams()).thenReturn(preferredPublicKeyCredentialParameters);
            RelyingPartyIdentity relyingPartyIdentity = mock(RelyingPartyIdentity.class);
            when(relyingParty.getIdentity()).thenReturn(relyingPartyIdentity);
            when(relyingPartyIdentity.getId()).thenReturn("relyingPartyId");

            whenNew(WebAuthnManager.class).withAnyArguments().thenReturn(webAuthnManager);
            when(webAuthnManager.parse(any(RegistrationRequest.class))).thenReturn(registrationData);
            when(webAuthnManager.validate(any(RegistrationData.class), any(RegistrationParameters.class)))
                    .thenReturn(registrationData);
        }

        if (Boolean.parseBoolean(mdsValidationEnabled)) {
            MetadataService metadataService = mock(MetadataService.class);
            DefaultCertPathTrustworthinessValidator certPathValidator = mock(
                    DefaultCertPathTrustworthinessValidator.class);
            when(fido2AuthenticatorServiceDataHolder.getMetadataService()).thenReturn(metadataService);
            when(metadataService.getDefaultCertPathTrustworthinessValidator()).thenReturn(certPathValidator);
        }

        mockStatic(FinishRegistrationOptions.class);
        FinishRegistrationOptions finishRegistrationOptions = mock(FinishRegistrationOptions.class);
        FinishRegistrationOptions.FinishRegistrationOptionsBuilder finishRegistrationOptionsBuilder =
                mock(FinishRegistrationOptions.FinishRegistrationOptionsBuilder.class);
        FinishRegistrationOptions.FinishRegistrationOptionsBuilder.MandatoryStages mandatoryStages1 =
                mock(FinishRegistrationOptions.FinishRegistrationOptionsBuilder.MandatoryStages.class);
        FinishRegistrationOptions.FinishRegistrationOptionsBuilder.MandatoryStages.Step2 step2Finish =
                mock(FinishRegistrationOptions.FinishRegistrationOptionsBuilder.MandatoryStages.Step2.class);

        when(FinishRegistrationOptions.builder()).thenReturn(mandatoryStages1);
        when(mandatoryStages1.request(any(PublicKeyCredentialCreationOptions.class))).thenReturn(step2Finish);
        when(step2Finish.response(any(PublicKeyCredential.class))).thenReturn(finishRegistrationOptionsBuilder);
        when(finishRegistrationOptionsBuilder.build()).thenReturn(finishRegistrationOptions);

        when(relyingParty.finishRegistration(any(FinishRegistrationOptions.class))).thenReturn(registrationResult);
        PublicKeyCredentialDescriptor descriptor = mock(PublicKeyCredentialDescriptor.class);
        ByteArray byteArray = new ByteArray(new byte[]{});
        UserIdentity userIdentity = mock(UserIdentity.class);
        when(registrationResult.getKeyId()).thenReturn(descriptor);
        when(descriptor.getId()).thenReturn(byteArray);
        when(registrationResult.getPublicKeyCose()).thenReturn(byteArray);
        when(publicKeyCredentialCreationOptions.getUser()).thenReturn(userIdentity);
        when(userIdentity.getId()).thenReturn(byteArray);
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = mock(AuthenticatorSelectionCriteria.class);
        when(publicKeyCredentialCreationOptions.getAuthenticatorSelection()).thenReturn(
                Optional.ofNullable(authenticatorSelectionCriteria));
        if (requireResidentKey) {
            when(authenticatorSelectionCriteria.getResidentKey()).thenReturn(Optional.ofNullable(
                    ResidentKeyRequirement.REQUIRED));

        } else {
            when(authenticatorSelectionCriteria.getResidentKey()).thenReturn(Optional.ofNullable(
                    ResidentKeyRequirement.DISCOURAGED));
        }
        mockStatic(RegisteredCredential.class);
        RegisteredCredential registeredCredential = mock(RegisteredCredential.class);
        RegisteredCredential.RegisteredCredentialBuilder registeredCredentialBuilder =
                mock(RegisteredCredential.RegisteredCredentialBuilder.class);
        RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages mandatoryStages2 =
                mock(RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages.class);
        RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages.Step2 step2RegisteredCredentials =
                mock(RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages.Step2.class);
        RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages.Step3 step3RegisteredCredentials =
                mock(RegisteredCredential.RegisteredCredentialBuilder.MandatoryStages.Step3.class);

        when(RegisteredCredential.builder()).thenReturn(mandatoryStages2);
        when(mandatoryStages2.credentialId(any(ByteArray.class))).thenReturn(step2RegisteredCredentials);
        when(step2RegisteredCredentials.userHandle(any(ByteArray.class))).thenReturn(step3RegisteredCredentials);
        when(step3RegisteredCredentials.publicKeyCose(any(ByteArray.class))).thenReturn(registeredCredentialBuilder);
        when(registeredCredentialBuilder.signatureCount(anyLong())).thenReturn(registeredCredentialBuilder);
        when(registeredCredentialBuilder.build()).thenReturn(registeredCredential);

        webAuthnService.finishFIDO2Registration(finishRegistrationResponseString);
    }

    @Test(description = "Test case for finishFIDO2Registration() method when the key is already registered",
            expectedExceptions = {FIDO2AuthenticatorClientException.class}, priority = 4)
    public void testFinishFIDO2RegistrationExistingKey() throws IOException, FIDO2AuthenticatorServerException,
            FIDO2AuthenticatorClientException {

        when(objectMapperMock.readValue(finishRegistrationResponseString, RegistrationResponse.class))
                .thenReturn(finishRegistrationResponse);
        when(fido2DeviceStoreDAO.getFIDO2RegistrationByUsernameAndCredentialId(anyString(), any(ByteArray.class)))
                .thenReturn(Optional.ofNullable(fido2CredentialRegistration));

        webAuthnService.finishFIDO2Registration(finishRegistrationResponseString);
    }

    @Test(description = "Test case for startAuthentication() method", priority = 5)
    public void testStartAuthentication() throws AuthenticationFailedException, JsonProcessingException {

        mockStatic(StartAssertionOptions.class);
        StartAssertionOptions.StartAssertionOptionsBuilder startAssertionOptionsBuilder =
                mock(StartAssertionOptions.StartAssertionOptionsBuilder.class);
        when(StartAssertionOptions.builder()).thenReturn(startAssertionOptionsBuilder);
        when(startAssertionOptionsBuilder.username(anyString())).thenReturn(startAssertionOptionsBuilder);
        when(relyingParty.startAssertion(any(StartAssertionOptions.class))).thenReturn(assertionRequest);
        when(FIDOUtil.writeJson(any(AssertionRequestWrapper.class))).thenReturn("assertionRequest");

        String response = webAuthnService.startAuthentication(USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN, ORIGIN);
        Assert.assertEquals(response, "assertionRequest");
    }

    @Test(description = "Test case for startUsernamelessAuthentication() method", priority = 6)
    public void testStartUsernamelessAuthentication() throws AuthenticationFailedException, JsonProcessingException {

        mockStatic(StartAssertionOptions.class);
        StartAssertionOptions.StartAssertionOptionsBuilder startAssertionOptionsBuilder =
                mock(StartAssertionOptions.StartAssertionOptionsBuilder.class);
        when(StartAssertionOptions.builder()).thenReturn(startAssertionOptionsBuilder);
        when(relyingParty.startAssertion(any(StartAssertionOptions.class))).thenReturn(assertionRequest);
        when(FIDOUtil.writeJson(any(AssertionRequestWrapper.class))).thenReturn("assertionRequest");

        String response = webAuthnService.startUsernamelessAuthentication(ORIGIN);
        Assert.assertEquals(response, "assertionRequest");
    }

    @Test(description = "Test case for finishAuthentication() method when assertion fails", expectedExceptions = {
            AuthenticationFailedException.class
    }, priority = 7)
    public void testFinishAuthenticationFailedAssertion() throws JsonProcessingException,
            MalformedURLException, AuthenticationFailedException, AssertionFailedException {

        when(objectMapperMock.readValue(finishAuthenticationResponseString, AssertionResponse.class))
                .thenReturn(finishAuthenticationResponse);
        when(fido2Cache.getValueFromCacheByRequestId(any(FIDO2CacheKey.class))).thenReturn(fido2CacheEntry);
        when(fido2CacheEntry.getAssertionRequest()).thenReturn("assertionRequest");
        when(fido2CacheEntry.getOrigin()).thenReturn(new URL(ORIGIN));
        when(objectMapperMock.readValue("assertionRequest", AssertionRequest.class)).thenReturn(assertionRequest);
        when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(assertionResult);
        when(assertionResult.isSuccess()).thenReturn(false);
        when(assertionResult.getUsername()).thenReturn(USERNAME);

        webAuthnService.finishAuthentication(USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN,
                finishAuthenticationResponseString);
    }

    @Test(description = "Test case for finishAuthentication() method when assertion success", priority = 8)
    public void testFinishAuthenticationSuccessfulAssertion() throws JsonProcessingException,
            MalformedURLException, AuthenticationFailedException, AssertionFailedException {

        when(objectMapperMock.readValue(finishAuthenticationResponseString, AssertionResponse.class))
                .thenReturn(finishAuthenticationResponse);
        when(fido2Cache.getValueFromCacheByRequestId(any(FIDO2CacheKey.class))).thenReturn(fido2CacheEntry);
        when(fido2CacheEntry.getAssertionRequest()).thenReturn("assertionRequest");
        when(fido2CacheEntry.getOrigin()).thenReturn(new URL(ORIGIN));
        when(objectMapperMock.readValue("assertionRequest", AssertionRequest.class)).thenReturn(assertionRequest);
        when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(assertionResult);
        when(assertionResult.isSuccess()).thenReturn(true);
        when(assertionResult.getUsername()).thenReturn(USERNAME);

        webAuthnService.finishAuthentication(USERNAME, TENANT_DOMAIN, USER_STORE_DOMAIN,
                finishAuthenticationResponseString);
    }

    @Test(description = "Test case for finishUsernamelessAuthentication() method when assertion fails",
            expectedExceptions = {AuthenticationFailedException.class}, priority = 9)
    public void testFinishUsernamelessAuthenticationFailedAssertion() throws JsonProcessingException,
            AuthenticationFailedException, MalformedURLException, AssertionFailedException {

        when(objectMapperMock.readValue(finishUsernamelessAuthenticationResponseString, AssertionResponse.class))
                .thenReturn(finishUsernamelessAuthenticationResponse);
        when(fido2Cache.getValueFromCacheByRequestId(any(FIDO2CacheKey.class))).thenReturn(fido2CacheEntry);
        when(fido2CacheEntry.getAssertionRequest()).thenReturn("assertionRequest");
        when(fido2CacheEntry.getOrigin()).thenReturn(new URL(ORIGIN));
        when(objectMapperMock.readValue("assertionRequest", AssertionRequest.class)).thenReturn(assertionRequest);
        when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(assertionResult);
        when(assertionResult.isSuccess()).thenReturn(false);
        when(assertionResult.getUsername()).thenReturn(USERNAME);

        webAuthnService.finishUsernamelessAuthentication(finishUsernamelessAuthenticationResponseString);
    }

    @Test(description = "Test case for finishUsernamelessAuthentication() method when assertion success",
            priority = 10)
    public void testFinishUsernamelessAuthenticationSuccessfulAssertion() throws JsonProcessingException,
            AuthenticationFailedException, MalformedURLException, AssertionFailedException {

        when(objectMapperMock.readValue(finishUsernamelessAuthenticationResponseString, AssertionResponse.class))
                .thenReturn(finishUsernamelessAuthenticationResponse);
        when(fido2Cache.getValueFromCacheByRequestId(any(FIDO2CacheKey.class))).thenReturn(fido2CacheEntry);
        when(fido2CacheEntry.getAssertionRequest()).thenReturn("assertionRequest");
        when(fido2CacheEntry.getOrigin()).thenReturn(new URL(ORIGIN));
        when(objectMapperMock.readValue("assertionRequest", AssertionRequest.class)).thenReturn(assertionRequest);
        when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(assertionResult);
        when(assertionResult.isSuccess()).thenReturn(true);
        when(assertionResult.getUsername()).thenReturn(USERNAME);

        AuthenticatedUser authenticatedUserResponse = webAuthnService.finishUsernamelessAuthentication(
                finishUsernamelessAuthenticationResponseString);
        Assert.assertEquals(authenticatedUserResponse.getUserName(), user.getUserName());
        Assert.assertEquals(authenticatedUserResponse.getTenantDomain(), user.getTenantDomain());
        Assert.assertEquals(authenticatedUserResponse.getUserStoreDomain(), user.getUserStoreDomain());
    }

    @Test(description = "Test case for getFIDO2DeviceMetaData() method", priority = 11)
    public void testGetFIDO2DeviceMetaData() throws FIDO2AuthenticatorServerException {

        Collection<FIDO2CredentialRegistration> response = webAuthnService.getFIDO2DeviceMetaData(USERNAME);
        Assert.assertNotNull(response.iterator().next());
    }

    @Test(description = "Test case for deregisterFIDO2Credential() method", priority = 12)
    public void testDeregisterFIDO2Credential() throws FIDO2AuthenticatorServerException,
            FIDO2AuthenticatorClientException, Base64UrlException {

        webAuthnService.deregisterFIDO2Credential(CREDENTIAL_ID);
    }

    @Test(description = "Test case for updateFIDO2DeviceDisplayName() method", priority = 13)
    public void testUpdateFIDO2DeviceDisplayName() throws FIDO2AuthenticatorServerException,
            FIDO2AuthenticatorClientException {

        webAuthnService.updateFIDO2DeviceDisplayName(CREDENTIAL_ID, "Updated display name");
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
        CarbonContext carbonContext = mock(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
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

    private void prepareResources() throws IOException {

        ObjectMapper objectMapper = JacksonCodecs.json();

        finishRegistrationResponseString = readResource("fido2-finish-registration-response.json",
                this.getClass());
        finishRegistrationResponse = objectMapper.readValue(finishRegistrationResponseString,
                RegistrationResponse.class);
        finishAuthenticationResponseString = readResource("fido2-finish-authentication-response.json",
                this.getClass());
        finishAuthenticationResponse = objectMapper.readValue(finishAuthenticationResponseString,
                AssertionResponse.class);
        finishUsernamelessAuthenticationResponseString = readResource(
                "fido2-finish-usernameless-authentication-response.json", this.getClass());
        finishUsernamelessAuthenticationResponse = objectMapper.readValue(
                finishUsernamelessAuthenticationResponseString, AssertionResponse.class);
    }
}
