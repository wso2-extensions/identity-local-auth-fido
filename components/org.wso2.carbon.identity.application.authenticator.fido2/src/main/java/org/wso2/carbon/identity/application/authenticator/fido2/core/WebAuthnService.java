/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2Cache;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheEntry;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheKey;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionRequestWrapper;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.RegistrationResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.SuccessfulAuthenticationResult;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.SuccessfulRegistrationResult;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@SuppressWarnings("ALL")
public class WebAuthnService {

    private static Log log = LogFactory.getLog(WebAuthnService.class);

    private final Clock clock = Clock.systemDefaultZone();
    private static final SecureRandom random = new SecureRandom();
    private static List<String> origins = new ArrayList<>();
    private final ObjectMapper jsonMapper = WebAuthnCodecs.json();
    private static final FIDO2DeviceStoreDAO userStorage = FIDO2DeviceStoreDAO.getInstance();

    private static volatile WebAuthnService webAuthnService;

    public static WebAuthnService getInstance() {

        if (webAuthnService == null) {
            synchronized (WebAuthnService.class) {
                if (webAuthnService == null) {
                    Object value = IdentityConfigParser.getInstance().getConfiguration()
                            .get(FIDO2AuthenticatorConstants.TRUSTED_ORIGINS);
                    if (value instanceof ArrayList) {
                        origins = (ArrayList)value;
                    } else {
                        origins = Arrays.asList((String)value);
                    }
                    webAuthnService = new WebAuthnService();
                    return webAuthnService;
                } else {
                    return webAuthnService;
                }
            }
        } else {
            return webAuthnService;
        }
    }

    private WebAuthnService() {
    }

    public Either<String, RegistrationRequest> startRegistration(@NonNull String origin)
            throws JsonProcessingException, FIDO2AuthenticatorException {

        if(!origins.contains(origin.trim())) {
            throw new FIDO2AuthenticatorException("FIDO device registration initialisation " +
                    "failed due to invalid origin");
        }

        URL originUrl = null;
        try {
            originUrl = new URL(origin);
        } catch (MalformedURLException e) {
            // Should not reach this point as the recieved origin is validated against whitelisted origins
        }
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        FIDOUser user = FIDOUtil.getUser();
        if (true) {
            PublicKeyCredentialCreationOptions credentialCreationOptions = relyingParty
                    .startRegistration(StartRegistrationOptions.builder()
                            .user(UserIdentity.builder().name(user.toString()).displayName(user.getUserName())
                            .id(generateRandom(32)).build()).build());
            RegistrationRequest request = new RegistrationRequest(user.toString(), generateRandom(32),
                    credentialCreationOptions);

            FIDO2Cache.getInstance().addToCacheByRequestId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                    new FIDO2CacheEntry(jsonMapper.writeValueAsString(request.getPublicKeyCredentialCreationOptions()),
                            null, originUrl));
            return Either.right(request);
        } else {
            return Either.left("The username \"" + user.toString() + "\" is already registered.");
        }
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson) throws
            FIDO2AuthenticatorException, FIDO2AuthenticatorServerException, IOException {

        RegistrationResponse response;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            log.error(MessageFormat.format("JSON error in finishRegistration; responseJson: {0}",
                    responseJson), e);
            return Either.left(Arrays.asList("Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if(cacheEntry != null) {
            publicKeyCredentialCreationOptions = jsonMapper.readValue(cacheEntry.getPublicKeyCredentialCreationOptions(),
                    PublicKeyCredentialCreationOptions.class);
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (publicKeyCredentialCreationOptions == null || relyingParty == null) {
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("fail finishRegistration responseJson: {0}", responseJson));
            }
            throw new FIDO2AuthenticatorException("Registration failed! No such registration in progress");
        } else {
            try {
                RegistrationResult registration = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                                .request(publicKeyCredentialCreationOptions)
                        .response(response.getCredential()).build()
                );

                addRegistration(publicKeyCredentialCreationOptions, response, registration);

            return Either.right(
                        new SuccessfulRegistrationResult(publicKeyCredentialCreationOptions, response, registration
                                .isAttestationTrusted()));
            } catch (RegistrationFailedException e) {
                throw new FIDO2AuthenticatorException("Registration failed!", e);
            } catch (IOException e) {
                throw new FIDO2AuthenticatorServerException("Registration failed unexpectedly; this is likely a bug.",e);
            }
        }
    }

    public Either<List<String>, AssertionRequestWrapper> startAuthentication(String username,
                                                                             String tenantDomain, String storeDomain,
                                                                             String appId)
            throws JsonProcessingException, FIDO2AuthenticatorException {

        URL originUrl = null;
        try {
            originUrl = new URL(appId);
        } catch (MalformedURLException e) {
            throw new FIDO2AuthenticatorException("Invalid AppID : " + appId);
        }

        User user = new User();
        user.setUserName(username);
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(storeDomain);
        if (userStorage.getRegistrationsByUsername(user.toString()).isEmpty()) {
            throw new FIDO2AuthenticatorException("The username \"" + user.toString() + "\" is not registered.");
        } else {
            RelyingParty relyingParty = buildRelyingParty(originUrl);
            AssertionRequestWrapper request = new AssertionRequestWrapper(
                    generateRandom(32), relyingParty.startAssertion(StartAssertionOptions.builder()
                    .username(user.toString()).build()));
            FIDO2Cache.getInstance().addToCacheByRequestWrapperId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                    new FIDO2CacheEntry(null, jsonMapper.writeValueAsString(request
                            .getRequest()), originUrl));
            return Either.right(request);
        }
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String username,
                                                                                     String tenantDomain,
                                                                                     String storeDomain,
                                                                                     String appId, String responseJson)
            throws IOException, FIDO2AuthenticatorException {

        User user = new User();
        user.setUserName(username);
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(storeDomain);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            if(log.isDebugEnabled()) {
                log.debug("Failed to decode response object", e);
            }
            return Either.left(Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));
        AssertionRequest request = null;
        RelyingParty relyingParty = null;
        if(cacheEntry != null) {
            request = jsonMapper.readValue(cacheEntry.getAssertionRequest(), AssertionRequest.class);
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (request == null) {
            throw new FIDO2AuthenticatorException("Assertion failed! No such assertion in progress.");
        } else {
            try {

                // Fixing Yubico issue
                PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential
                        = response.getCredential();
                if(response.getCredential().getResponse().getUserHandle().isPresent() &&
                        response.getCredential().getResponse().getUserHandle().get().getBase64().equals("")) {

                    AuthenticatorAssertionResponse authResponse = credential.getResponse().toBuilder()
                            .authenticatorData(credential.getResponse().getAuthenticatorData())
                            .clientDataJSON(credential.getResponse().getClientDataJSON())
                            .signature(credential.getResponse().getSignature())
                            .userHandle(Optional.empty())
                            .build();

                    credential = response.getCredential().toBuilder()
                            .id(credential.getId())
                            .clientExtensionResults(credential.getClientExtensionResults())
                            .response(authResponse)
                            .type(credential.getType())
                            .build();
                }

                AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                        .request(request).response(credential).build());

                if (result.isSuccess()) {
                    try {
                        userStorage.updateSignatureCount(result);
                    } catch (Exception e) {
                        log.error(MessageFormat.format("Failed to update signature count for user \"{0}\", " +
                                        "credential \"{1}\"", result.getUsername(), response
                                .getCredential().getId()), e);
                    }

                    return Either.right(
                            new SuccessfulAuthenticationResult(request, response, userStorage
                                    .getRegistrationsByUsername(result.getUsername()), result.getWarnings()));
                } else {
                    return Either.left(Collections.singletonList("Assertion failed: Invalid assertion."));
                }
            } catch (AssertionFailedException e) {
                log.error("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
            } catch (Exception e) {
                log.error("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    public Collection<CredentialRegistration> getDeviceMetaData(String username) {

        return userStorage.getRegistrationsByUsername(User.getUserFromUserName(username).toString());
    }

    private static ByteArray generateRandom(int length) {

        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    private CredentialRegistration addRegistration(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                                   RegistrationResponse response,
                                                   RegistrationResult registration) throws IOException {

        UserIdentity userIdentity = publicKeyCredentialCreationOptions.getUser();
        RegisteredCredential credential = RegisteredCredential.builder()
                .credentialId(registration.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(registration.getPublicKeyCose())
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                        .getSignatureCounter())
                .build();


        CredentialRegistration reg = CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .registrationTime(clock.instant())
                .credential(credential)
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                        .getSignatureCounter())
                .attestationMetadata(registration.getAttestationMetadata())
                .build();
        userStorage.addRegistrationByUsername(userIdentity.getName(), reg);

        return reg;
    }


    public void deregisterCredential(String credentialId) throws IOException {

        if (credentialId == null || credentialId.getBytes().length == 0) {
            throw new IOException("Credential ID must not be empty.");
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new IOException("Credential ID is not valid Base64Url data: " + credentialId);
        }

        FIDOUser user = FIDOUtil.getUser();
        Optional<CredentialRegistration> credReg = userStorage.getRegistrationByUsernameAndCredentialId(user.toString(),
                identifier);

        if (credReg.isPresent()) {
            userStorage.removeRegistrationByUsername(user.toString(), credReg.get());
        } else {
            throw new IOException("Credential ID not registered:" + credentialId);
        }
    }

    private RelyingParty buildRelyingParty(URL originUrl) {

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(originUrl.getHost())
                .name(FIDO2AuthenticatorConstants.APPLICATION_NAME)
                .build();

        RelyingParty relyingParty = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(userStorage)
                .origins(new HashSet<String>(origins))
                .build();

        return relyingParty;
    }
}
