package org.wso2.carbon.identity.application.authenticator.fido2.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.mockito.Mock;
import org.mockito.Spy;
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
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2Cache;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.nio.file.Paths;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anySet;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@PrepareForTest({FIDO2DeviceStoreDAO.class, IdentityUtil.class, JacksonCodecs.class, IdentityConfigParser.class,
        UserCoreUtil.class,
        CarbonContext.class, PrivilegedCarbonContext.class, User.class, RelyingParty.class,
        PublicKeyCredentialCreationOptions.class, StartRegistrationOptions.class, FIDO2Cache.class,
        IdentityTenantUtil.class, FIDO2AuthenticatorServiceComponent.class})
public class WebAuthnServiceTest {

    private String ORIGIN = "https://localhost:9443";
    private final String USERNAME = "admin";
    private final String TENANT_QUALIFIED_USERNAME = "admin@carbon.super";
    private final String DISPLAY_NAME = "Administrator";
    private final String FIRST_NAME = "admin";
    private final String LAST_NAME = "admin";
    private final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String DISPLAY_NAME_CLAIM_URL = "http://wso2.org/claims/displayName";
    private static final String FIRST_NAME_CLAIM_URL = "http://wso2.org/claims/givenname";
    private static final String LAST_NAME_CLAIM_URL = "http://wso2.org/claims/lastname";

    private WebAuthnService webAuthnService;
    private Map<String, Object> identityConfig = new HashMap<>();
    private ArrayList<String> trustedOrigins = new ArrayList<>();
    private CarbonContext carbonContext;

    @Mock
    private FIDO2DeviceStoreDAO fido2DeviceStoreDAO;
    @Mock
    private IdentityConfigParser identityConfigParser;
    @Spy
    private ObjectMapper objectMapper = JacksonCodecs.json();
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
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;

    @BeforeMethod
    public void setUp() throws UserStoreException {
        initMocks(this);
        mockStatic(FIDO2DeviceStoreDAO.class);
        when(FIDO2DeviceStoreDAO.getInstance()).thenReturn(fido2DeviceStoreDAO);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty("FIDO.UserResponseTimeout")).thenReturn("300");
        mockStatic(JacksonCodecs.class);
        when(JacksonCodecs.json()).thenReturn(objectMapper);
        webAuthnService = new WebAuthnService();

        trustedOrigins.add("https://localhost:9443");
        identityConfig.put(FIDO2AuthenticatorConstants.TRUSTED_ORIGINS, trustedOrigins);
        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(identityConfig);
        when(IdentityUtil.fillURLPlaceholders(anyString())).thenReturn(ORIGIN);

        mockCarbonContext();
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn(TENANT_QUALIFIED_USERNAME);

        mockStatic(User.class);
        mockStatic(RelyingParty.class);
        mockStatic(RelyingParty.RelyingPartyBuilder.class);
        when(RelyingParty.builder()).thenReturn(mandatoryStages);
        when(mandatoryStages.identity(any())).thenReturn(step2);
        when(step2.credentialRepository(any())).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.origins(anySet())).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.attestationConveyancePreference(AttestationConveyancePreference.DIRECT)).thenReturn(relyingPartyBuilder);
        when(relyingPartyBuilder.allowUnrequestedExtensions(anyBoolean())).thenReturn(relyingPartyBuilder);
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
    }

    @Test(description = "Test case for startFIDO2Registration() method")
    public void testStartFIDO2Registration() throws FIDO2AuthenticatorClientException, JsonProcessingException {

        User user = new User();
        user.setUserName(USERNAME + "@" + SUPER_TENANT_DOMAIN_NAME);
        user.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        when(User.getUserFromUserName(anyString())).thenReturn(user);

        mockStatic(StartRegistrationOptions.class);
        StartRegistrationOptions startRegistrationOptions = mock(StartRegistrationOptions.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder startRegistrationOptionsBuilder =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.class);
        StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages mandatoryStages1 =
                mock(StartRegistrationOptions.StartRegistrationOptionsBuilder.MandatoryStages.class);
        when(StartRegistrationOptions.builder()).thenReturn(mandatoryStages1);
        when(mandatoryStages1.user(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.timeout(anyLong())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.authenticatorSelection(any(AuthenticatorSelectionCriteria.class))).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.extensions(any())).thenReturn(startRegistrationOptionsBuilder);
        when(startRegistrationOptionsBuilder.build()).thenReturn(startRegistrationOptions);

        PublicKeyCredentialCreationOptions credentialCreationOptions = mock(PublicKeyCredentialCreationOptions.class);
        when(relyingParty.startRegistration(any())).thenReturn(credentialCreationOptions);
        when(objectMapper.writeValueAsString(any())).thenReturn("dummyValueAsString");

        Either<String, FIDO2RegistrationRequest> result = webAuthnService.startFIDO2Registration(ORIGIN);
        Assert.assertTrue(result.isRight());
    }

//    @Test(description = "Test case for startFIDO2UsernamelessRegistration() method")
//    public void testStartFIDO2UsernamelessRegistration() {
//
//        //
//    }
//
//    @Test(description = "Test case for finishFIDO2Registration() method")
//    public void testFinishFIDO2Registration() {
//
//        //
//    }
//
//    @Test(description = "Test case for startAuthentication() method")
//    public void testStartAuthentication() {
//
//        //
//    }
//
//    @Test(description = "Test case for startUsernamelessAuthentication() method")
//    public void testStartUsernamelessAuthentication() {
//
//        //
//    }
//
//    @Test(description = "Test case for finishAuthentication() method")
//    public void testFinishAuthentication() {
//
//        //
//    }
//
//    @Test(description = "Test case for finishUsernamelessAuthentication() method")
//    public void testFinishUsernamelessAuthentication() {
//
//        //
//    }
//
//    @Test(description = "Test case for getFIDO2DeviceMetaData() method")
//    public void testGetFIDO2DeviceMetaData() {
//
//        //
//    }
//
//    @Test(description = "Test case for deregisterFIDO2Credential() method")
//    public void testDeregisterFIDO2Credential() {
//
//        //
//    }
//
//    @Test(description = "Test case for updateFIDO2DeviceDisplayName() method")
//    public void testUpdateFIDO2DeviceDisplayName() {
//
//        //
//    }

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
