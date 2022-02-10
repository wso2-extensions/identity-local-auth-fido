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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.InternetDomainName;
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
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2Cache;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheEntry;
import org.wso2.carbon.identity.application.authenticator.fido2.cache.FIDO2CacheKey;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionRequestWrapper;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.RegistrationResponse;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.SuccessfulAuthenticationResult;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.SuccessfulRegistrationResult;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import static com.yubico.webauthn.data.UserVerificationRequirement.PREFERRED;

/**
 * FIDO2 core APIs.
 */
public class WebAuthnService {

    private static final Log log = LogFactory.getLog(WebAuthnService.class);

    private static final int USER_HANDLE_LENGTH = 32;

    private final Clock clock = Clock.systemDefaultZone();
    private static final SecureRandom random = new SecureRandom();
    private final ObjectMapper jsonMapper = JacksonCodecs.json();
    private static final FIDO2DeviceStoreDAO userStorage = FIDO2DeviceStoreDAO.getInstance();

    private static ArrayList origins = null;

    private static final String userResponseTimeout = IdentityUtil.getProperty("FIDO.UserResponseTimeout");
    private static final String displayNameClaimURL = "http://wso2.org/claims/displayName";
    private static final String firstNameClaimURL = "http://wso2.org/claims/givenname";
    private static final String lastNameClaimURL = "http://wso2.org/claims/lastname";

    @Deprecated
    /** @deprecated Please use {@link #startFIDO2Registration(String)} instead. */
    public Either<String, RegistrationRequest> startRegistration(@NonNull String origin)
            throws JsonProcessingException, FIDO2AuthenticatorException {

        readTrustedOrigins();
        if (!origins.contains(origin.trim())) {
            throw new FIDO2AuthenticatorException(FIDO2AuthenticatorConstants.INVALID_ORIGIN_MESSAGE);
        }

        URL originUrl;
        try {
            originUrl = new URL(origin);
        } catch (MalformedURLException e) {
            throw new FIDO2AuthenticatorException(FIDO2AuthenticatorConstants.INVALID_ORIGIN_MESSAGE);
        }
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        PublicKeyCredentialCreationOptions credentialCreationOptions = relyingParty
                .startRegistration(buildStartRegistrationOptions(user, false));

        RegistrationRequest request = new RegistrationRequest(user.toString(), generateRandom(),
                credentialCreationOptions);

        FIDO2Cache.getInstance().addToCacheByRequestId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                new FIDO2CacheEntry(jsonMapper.writeValueAsString(request.getPublicKeyCredentialCreationOptions()),
                        null, originUrl));
        return Either.right(request);
    }

    /**
     * Triggers FIDO2 start registration flow.
     *
     * @param origin FIDO2 trusted origin.
     * @return FIDO2 registration request.
     * @throws JsonProcessingException
     * @throws FIDO2AuthenticatorClientException
     */
    public Either<String, FIDO2RegistrationRequest> startFIDO2Registration(@NonNull String origin)
            throws JsonProcessingException, FIDO2AuthenticatorClientException {

        validateFIDO2TrustedOrigin(origin);
        URL originUrl = getOriginUrl(origin);
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        PublicKeyCredentialCreationOptions credentialCreationOptions;
        try {
            // Store the user object in a thread local property.
            IdentityUtil.threadLocalProperties.get().put(FIDO2AuthenticatorConstants.FIDO2_USER, user);
            credentialCreationOptions = relyingParty.startRegistration(buildStartRegistrationOptions(user, false));
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(FIDO2AuthenticatorConstants.FIDO2_USER);
        }

        FIDO2RegistrationRequest request = new FIDO2RegistrationRequest(generateRandom(), credentialCreationOptions);

        FIDO2Cache.getInstance().addToCacheByRequestId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                new FIDO2CacheEntry(jsonMapper.writeValueAsString(request.getPublicKeyCredentialCreationOptions()),
                        null, originUrl));
        return Either.right(request);
    }

    /**
     * Triggers FIDO2 start usernameless registration flow.
     *
     * @param origin FIDO2 trusted origin.
     * @return FIDO2 registration request.
     * @throws JsonProcessingException
     * @throws FIDO2AuthenticatorClientException
     */
    public Either<String, FIDO2RegistrationRequest> startFIDO2UsernamelessRegistration(@NonNull String origin)
            throws JsonProcessingException, FIDO2AuthenticatorClientException {

        validateFIDO2TrustedOrigin(origin);
        URL originUrl = getOriginUrl(origin);
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        PublicKeyCredentialCreationOptions credentialCreationOptions;
        try {
            // Store the user object in a thread local property.
            IdentityUtil.threadLocalProperties.get().put(FIDO2AuthenticatorConstants.FIDO2_USER, user);
            credentialCreationOptions = relyingParty.startRegistration(buildStartRegistrationOptions(user, true));
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(FIDO2AuthenticatorConstants.FIDO2_USER);
        }

        FIDO2RegistrationRequest request = new FIDO2RegistrationRequest(generateRandom(), credentialCreationOptions);
        FIDO2Cache.getInstance().addToCacheByRequestId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                new FIDO2CacheEntry(jsonMapper.writeValueAsString(request.getPublicKeyCredentialCreationOptions()),
                        null, originUrl));

        return Either.right(request);
    }

    @Deprecated
    /** @deprecated Please use {@link #finishFIDO2Registration(String)} instead. */
    public void finishRegistration(String challengeResponse) throws FIDO2AuthenticatorException, IOException {

        RegistrationResponse response;
        try {
            response = jsonMapper.readValue(challengeResponse, RegistrationResponse.class);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(FIDO2AuthenticatorConstants.DECODING_FAILED_MESSAGE, e);
            }
            throw new FIDO2AuthenticatorException(FIDO2AuthenticatorConstants.DECODING_FAILED_MESSAGE, e);
        }

        User user = getPrivilegedUser();
        if (FIDO2DeviceStoreDAO.getInstance().getFIDO2RegistrationByUsernameAndCredentialId(user.toString(),
                response.getCredential().getId()).isPresent()) {
            throw new FIDO2AuthenticatorException("The username \"" + user + "\" is already registered.");
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if (cacheEntry != null) {
            publicKeyCredentialCreationOptions = jsonMapper.readValue(cacheEntry.getPublicKeyCredentialCreationOptions(),
                    PublicKeyCredentialCreationOptions.class);
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (publicKeyCredentialCreationOptions == null || relyingParty == null) {
            String message = "Registration failed! No such registration in progress";
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("Fail finishRegistration challengeResponse: {0}", challengeResponse));
            }
            throw new FIDO2AuthenticatorException(message);
        } else {
            try {
                RegistrationResult registration = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                        .request(publicKeyCredentialCreationOptions)
                        .response(response.getCredential()).build()
                );

                addRegistration(publicKeyCredentialCreationOptions, response, registration);

                Either.right(
                        new SuccessfulRegistrationResult(publicKeyCredentialCreationOptions, response, registration
                                .isAttestationTrusted()));
            } catch (RegistrationFailedException e) {
                throw new FIDO2AuthenticatorException("Registration failed!", e);
            } catch (IOException e) {
                throw new FIDO2AuthenticatorServerException("Registration failed unexpectedly; this is likely a bug.", e);
            }
        }
    }

    /**
     * Completed FIDO2 device registration flow.
     *
     * @param challengeResponse Challenge response.
     * @throws FIDO2AuthenticatorServerException
     * @throws FIDO2AuthenticatorClientException
     */
    public void finishFIDO2Registration(String challengeResponse) throws FIDO2AuthenticatorServerException,
            FIDO2AuthenticatorClientException {

        RegistrationResponse response;
        try {
            response = jsonMapper.readValue(challengeResponse, RegistrationResponse.class);
        } catch (JsonParseException | JsonMappingException e) {
            throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST
                            .getErrorCode(), e);
        } catch (IOException e) {
            throw new FIDO2AuthenticatorServerException(FIDO2AuthenticatorConstants.DECODING_FAILED_MESSAGE, e);
        }

        User user = getPrivilegedUser();
        if(FIDO2DeviceStoreDAO.getInstance().getFIDO2RegistrationByUsernameAndCredentialId(user.toString(),
                response.getCredential().getId()).isPresent()) {
            throw new FIDO2AuthenticatorClientException("The username \"" + user + "\" is already registered.",
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS.getErrorCode());
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if (cacheEntry != null) {
            try {
                publicKeyCredentialCreationOptions = jsonMapper.readValue(cacheEntry.getPublicKeyCredentialCreationOptions(),
                        PublicKeyCredentialCreationOptions.class);
            } catch (JsonParseException | JsonMappingException e) {
                throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                        FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                                .ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode(), e);
            } catch (IOException e) {
                throw new FIDO2AuthenticatorServerException(FIDO2AuthenticatorConstants.DECODING_FAILED_MESSAGE, e);
            }
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (publicKeyCredentialCreationOptions == null || relyingParty == null) {
            String message = "Registration failed! No such registration in progress";
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("Fail finishRegistration challengeResponse: {0}", challengeResponse));
            }
            throw new FIDO2AuthenticatorClientException(message, FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.
                    ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode());
        } else {
            try {
                RegistrationResult registration = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                        .request(publicKeyCredentialCreationOptions)
                        .response(response.getCredential()).build()
                );

                try {
                    // Store the user object in a thread local property.
                    IdentityUtil.threadLocalProperties.get().put(FIDO2AuthenticatorConstants.FIDO2_USER, user);
                    addFIDO2Registration(publicKeyCredentialCreationOptions, response, registration);
                } finally {
                    IdentityUtil.threadLocalProperties.get().remove(FIDO2AuthenticatorConstants.FIDO2_USER);
                }

                Either.right(
                        new SuccessfulRegistrationResult(publicKeyCredentialCreationOptions, response, registration
                                .isAttestationTrusted()));
            } catch (RegistrationFailedException e) {
                throw new FIDO2AuthenticatorServerException("Registration failed!", e);
            }
        }
    }

    public String startAuthentication(String username, String tenantDomain, String storeDomain,
                                      String appId) throws AuthenticationFailedException {

        URL originUrl;
        try {
            originUrl = new URL(appId);

            User user = new User();
            user.setUserName(username);
            user.setTenantDomain(tenantDomain);
            user.setUserStoreDomain(storeDomain);
            if (userStorage.getFIDO2RegistrationsByUsername(user.toString()).isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No registered device found for user :" + user.toString());
                }
                return null;
            } else {
                RelyingParty relyingParty = buildRelyingParty(originUrl);
                AssertionRequestWrapper request = new AssertionRequestWrapper(
                        generateRandom(), relyingParty.startAssertion(StartAssertionOptions.builder()
                        .username(user.toString()).build()));
                FIDO2Cache.getInstance().addToCacheByRequestWrapperId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                        new FIDO2CacheEntry(null, jsonMapper.writeValueAsString(request
                                .getRequest()), originUrl));
                return FIDOUtil.writeJson(request);
            }
        } catch (MalformedURLException | JsonProcessingException | FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }
    }

    /**
     * Initiate usernameless authentication flow.
     *
     * @param appId Application Id resolved from the FIDO2 trusted origin.
     * @return Assertion request.
     * @throws AuthenticationFailedException
     */
    public String startUsernamelessAuthentication(String appId) throws AuthenticationFailedException {

        URL originUrl;
        try {
            originUrl = new URL(appId);
            RelyingParty relyingParty = buildRelyingParty(originUrl);
            AssertionRequestWrapper request = new AssertionRequestWrapper(generateRandom(),
                    relyingParty.startAssertion(StartAssertionOptions.builder().build()));
            FIDO2Cache.getInstance().addToCacheByRequestWrapperId(new FIDO2CacheKey(request.getRequestId().getBase64()),
                    new FIDO2CacheEntry(null, jsonMapper.writeValueAsString(request
                            .getRequest()), originUrl));
            return FIDOUtil.writeJson(request);
        } catch (MalformedURLException | JsonProcessingException e) {
            throw new AuthenticationFailedException("Usernameless authentication initialization failed for the " +
                    "application with app id: " + appId, e);
        }
    }

    public void finishAuthentication(String username, String tenantDomain, String storeDomain, String responseJson)
            throws AuthenticationFailedException {

        User user = new User();
        user.setUserName(username);
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(storeDomain);

        final AssertionResponse response;
        AssertionRequest request = null;
        RelyingParty relyingParty = null;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
            String requestId = response.getRequestId().getBase64();
            FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

            if (cacheEntry != null) {
                request = jsonMapper.readValue(cacheEntry.getAssertionRequest(), AssertionRequest.class);
                relyingParty = buildRelyingParty(cacheEntry.getOrigin());
                FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Assertion failed! Failed to decode response object.", e);
        }
        if (request == null) {
            throw new AuthenticationFailedException("Assertion failed! No such assertion in progress.");
        } else {
            try {
                PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential
                        = getPublicKeyCredential(response);
                AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                        .request(request).response(credential).build());

                if (result.isSuccess()) {
                    try {
                        userStorage.updateFIDO2SignatureCount(result);
                    } catch (Exception e) {
                        log.error(MessageFormat.format("Failed to update signature count for user \"{0}\", " +
                                "credential \"{1}\"", result.getUsername(), response
                                .getCredential().getId()), e);
                    }

                    new SuccessfulAuthenticationResult(request, response, userStorage
                            .getFIDO2RegistrationsByUsername(result.getUsername()), result.getWarnings());
                } else {
                    throw new AuthenticationFailedException("Assertion failed: Invalid assertion.");
                }
            } catch (AssertionFailedException e) {
                throw new AuthenticationFailedException("Assertion failed!", e);
            } catch (Exception e) {
                throw new AuthenticationFailedException("Assertion failed unexpectedly; this is likely a bug.", e);
            }
        }
    }

    /**
     * Complete usernameless authentication flow.
     *
     * @param responseJson JSON response received from the client.
     * @return Authenticated user.
     * @throws AuthenticationFailedException
     */
    public AuthenticatedUser finishUsernamelessAuthentication(String responseJson)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        final AssertionResponse response = getAssertionResponse(responseJson);
        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry =
                FIDO2Cache.getInstance().getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));
        if (cacheEntry == null) {
            throw new AuthenticationFailedException("Assertion failed! No cache entry can be found for request id: " +
                    requestId);
        }
        AssertionRequest request = getAssertionRequest(cacheEntry);
        RelyingParty relyingParty = buildRelyingParty(cacheEntry.getOrigin());
        FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        AssertionResult result = getAssertionResult(request, response, relyingParty);
        if (result.isSuccess()) {
            try {
                User user = User.getUserFromUserName(result.getUsername());
                authenticatedUser.setUserName(user.getUserName());
                authenticatedUser.setTenantDomain(user.getTenantDomain());
                authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());
                userStorage.updateFIDO2SignatureCount(result);

                new SuccessfulAuthenticationResult(request, response,
                        userStorage.getFIDO2RegistrationsByUsername(result.getUsername()), result.getWarnings());
            } catch (FIDO2AuthenticatorServerException e) {
                throw new AuthenticationFailedException("Error in usernameless authentication flow.", e);
            }
        } else {
            throw new AuthenticationFailedException("Assertion failed: Invalid assertion.");
        }

        return authenticatedUser;
    }

    @Deprecated
    /** @deprecated Please use {@link #getFIDO2DeviceMetaData(String)} instead. */
    public Collection<CredentialRegistration> getDeviceMetaData(String username) {

        return userStorage.getRegistrationsByUsername(User.getUserFromUserName(username).toString());
    }

    /**
     * Retrieve FIDO2 device meta data for a particular user.
     *
     * @param username Username.
     * @return All FIDO2 device meta data for a user as a collection.
     * @throws FIDO2AuthenticatorServerException
     */
    public Collection<FIDO2CredentialRegistration> getFIDO2DeviceMetaData(String username) throws
            FIDO2AuthenticatorServerException {

        return userStorage.getFIDO2RegistrationsByUsername(User.getUserFromUserName(username).toString());
    }

    @Deprecated
    /** @deprecated Please use {@link #deregisterFIDO2Credential(String)} instead. */
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

        User user = User.getUserFromUserName(CarbonContext.getThreadLocalCarbonContext().getUsername());
        user.setTenantDomain(CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        Optional<CredentialRegistration> credReg = userStorage.getRegistrationByUsernameAndCredentialId(user.toString(),
                identifier);

        if (credReg.isPresent()) {
            userStorage.removeRegistrationByUsername(user.toString(), credReg.get());
        } else {
            throw new IOException("Credential ID not registered:" + credentialId);
        }
    }

    /**
     * Removes the FIDO2 device registration via the credential ID.
     *
     * @param credentialId Credential ID.
     * @throws FIDO2AuthenticatorServerException
     * @throws FIDO2AuthenticatorClientException
     */
    public void deregisterFIDO2Credential(String credentialId) throws FIDO2AuthenticatorServerException,
            FIDO2AuthenticatorClientException {

        if (StringUtils.isBlank(credentialId)) {
            throw new FIDO2AuthenticatorClientException("Credential ID must not be empty.",
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("Credential ID is not valid Base64Url data: " + credentialId,
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        Optional<FIDO2CredentialRegistration> credReg = userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user
                .toString(), identifier);

        if (credReg.isPresent()) {
            userStorage.removeFIDO2RegistrationByUsername(user.toString(), credReg.get());
        } else {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
        }
    }

    /**
     * Update the display name of a registered device.
     *
     * @param credentialId   Credential ID.
     * @param newDisplayName New display name to be updated.
     * @throws FIDO2AuthenticatorClientException
     * @throws FIDO2AuthenticatorServerException
     */
    public void updateFIDO2DeviceDisplayName(String credentialId, String newDisplayName)
            throws FIDO2AuthenticatorClientException, FIDO2AuthenticatorServerException {

        if (StringUtils.isBlank(credentialId)) {
            throw new FIDO2AuthenticatorClientException("Credential ID must not be empty.",
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("The Credential ID: " + credentialId + " is not a valid " +
                    "Base64Url data.", FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                    .ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        Optional<FIDO2CredentialRegistration> credentialRegistration =
                userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user.toString(), identifier);

        if (!credentialRegistration.isPresent()) {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes
                            .ERROR_CODE_UPDATE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
        }
        userStorage.updateFIDO2DeviceDisplayName(user, credentialRegistration.get(), newDisplayName);
    }

    private RelyingParty buildRelyingParty(URL originUrl) {

        readTrustedOrigins();
        String rpId;

        try {
            InternetDomainName internetDomainName = InternetDomainName.from(originUrl.getHost());
            rpId = internetDomainName.hasPublicSuffix() ? internetDomainName.topPrivateDomain().toString()
                    : originUrl.getHost();
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid domain name: '" + originUrl.getHost()
                        + "' received for internet domain name creation. Defaulting to origin host.");
            }
            rpId = originUrl.getHost();
        }

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(rpId)
                .name(FIDO2AuthenticatorConstants.APPLICATION_NAME)
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(userStorage)
                .origins(new HashSet<String>(origins))
                .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
                .allowUnrequestedExtensions(true)
                .build();
    }

    @Deprecated
    /** @deprecated Please use {@link #addFIDO2Registration(PublicKeyCredentialCreationOptions, RegistrationResponse,
     *  RegistrationResult)} instead.
     */
    private void addRegistration(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
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
    }

    private void addFIDO2Registration(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                      RegistrationResponse response,
                                      RegistrationResult registration) throws FIDO2AuthenticatorServerException {

        UserIdentity userIdentity = publicKeyCredentialCreationOptions.getUser();
        RegisteredCredential credential = RegisteredCredential.builder()
                .credentialId(registration.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(registration.getPublicKeyCose())
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                        .getSignatureCounter())
                .build();

        boolean requireResidentKey = false;
        if (publicKeyCredentialCreationOptions.getAuthenticatorSelection().isPresent()) {
            requireResidentKey =
                    publicKeyCredentialCreationOptions.getAuthenticatorSelection().get().isRequireResidentKey();
        }

        FIDO2CredentialRegistration reg = FIDO2CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .registrationTime(clock.instant())
                .credential(credential)
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                        .getSignatureCounter())
                .attestationMetadata(registration.getAttestationMetadata())
                .displayName(null)
                .isUsernamelessSupported(requireResidentKey)
                .build();
        userStorage.addFIDO2RegistrationByUsername(userIdentity.getName(), reg);
    }

    private static ByteArray generateRandom() {

        byte[] bytes = new byte[WebAuthnService.USER_HANDLE_LENGTH];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    private StartRegistrationOptions buildStartRegistrationOptions(User user, boolean requireResidentKey) throws FIDO2AuthenticatorClientException {

        try {
            return StartRegistrationOptions.builder()
                    .user(buildUserIdentity(user))
                    .timeout(Integer.parseInt(userResponseTimeout))
                    .authenticatorSelection(buildAuthenticatorSelection(requireResidentKey))
                    .extensions(RegistrationExtensionInputs.builder().build())
                    .build();
        } catch (FIDO2AuthenticatorServerException e) {
            throw new FIDO2AuthenticatorClientException("Unable to create registration options", e);
        }

    }

    private AuthenticatorSelectionCriteria buildAuthenticatorSelection(boolean requireResidentKey) {

        return AuthenticatorSelectionCriteria.builder()
                .requireResidentKey(requireResidentKey)
                .userVerification(PREFERRED)
                .build();
    }

    private String getUserDisplayName(User user) throws FIDO2AuthenticatorServerException {

        String displayName;
        displayName = getUserClaimValue(user, displayNameClaimURL);
        // If the displayName is not available, build the displayName with firstName and lastName.
        if (StringUtils.isBlank(displayName)) {
            String firstName = getUserClaimValue(user, firstNameClaimURL);
            String lastName = getUserClaimValue(user, lastNameClaimURL);
            if (StringUtils.isNotBlank(firstName) || StringUtils.isNotBlank(lastName)) {
                displayName = StringUtils.join(new String[] { firstName, lastName }, " ");
            } else {
                // If the firstName or the lastName is not available, set the username as the displayName.
                displayName = user.getUserName();
            }
        }
        return StringUtils.trim(displayName);
    }

    private String getUserClaimValue(User user, String claimURL) throws FIDO2AuthenticatorServerException {

        String claimValue;
        try {
            UserStoreManager userStoreManager = getUserStoreManager(user);
            claimValue = userStoreManager.getUserClaimValue(user.getUserName(), claimURL, null);
        } catch (UserStoreException e) {
            throw new FIDO2AuthenticatorServerException(
                    "Failed retrieving user claim: " + claimURL + " for the user: " + user, e);
        }
        return claimValue;
    }

    private UserStoreManager getUserStoreManager(User user) throws UserStoreException {

        UserStoreManager userStoreManager = FIDO2AuthenticatorServiceComponent.getRealmService()
                .getTenantUserRealm(IdentityTenantUtil.getTenantId(user.getTenantDomain())).getUserStoreManager();
        if (userStoreManager instanceof org.wso2.carbon.user.core.UserStoreManager) {
            return ((org.wso2.carbon.user.core.UserStoreManager) userStoreManager).getSecondaryUserStoreManager(
                    user.getUserStoreDomain());
        }
        if (log.isDebugEnabled()) {
            String debugLog = String.format(
                    "Unable to resolve the corresponding user store manager for the domain: %s, "
                            + "as the provided user store manager: %s, is not an instance of "
                            + "org.wso2.carbon.user.core.UserStoreManager. Therefore returning the user store "
                            + "manager: %s, from the realm.", user.getUserStoreDomain(), userStoreManager.getClass(),
                    userStoreManager.getClass());
            log.debug(debugLog);
        }
        return userStoreManager;
    }

    private UserIdentity buildUserIdentity(User user) throws FIDO2AuthenticatorServerException {

        return UserIdentity.builder().name(user.getUserName()).displayName(getUserDisplayName(user))
                .id(generateRandom()).build();
    }

    private User getPrivilegedUser() {

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        return user;
    }

    private void readTrustedOrigins() {

        if (origins == null) {
            Object value = IdentityConfigParser.getInstance().getConfiguration()
                    .get(FIDO2AuthenticatorConstants.TRUSTED_ORIGINS);
            if (value == null) {
                origins = new ArrayList<>();
            } else if (value instanceof ArrayList) {
                origins = (ArrayList)value;
            } else {
                origins = new ArrayList<>(Arrays.asList((String) value));
            }
            origins.replaceAll(i -> IdentityUtil.fillURLPlaceholders((String)i));
        }
    }

    private AssertionResult getAssertionResult(AssertionRequest request, AssertionResponse response,
                                               RelyingParty relyingParty) throws AuthenticationFailedException {

        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    getPublicKeyCredential(response);

            return relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request).response(credential).build());
        } catch (AssertionFailedException e) {
            throw new AuthenticationFailedException("Assertion failed while finishing the assertion to retrieve the " +
                    "assertion result.", e);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Assertion failed unexpectedly; this is likely a bug.", e);
        }
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> getPublicKeyCredential
            (AssertionResponse response) throws IOException, Base64UrlException {

        // Fixing Yubico issue.
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                response.getCredential();
        if (response.getCredential().getResponse().getUserHandle().isPresent() &&
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

        return credential;
    }

    private AssertionResponse getAssertionResponse(String responseJson) throws AuthenticationFailedException {

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Assertion for finish authentication flow failed due to failure " +
                    "in decoding json response: " + responseJson, e);
        }

        return response;
    }

    private AssertionRequest getAssertionRequest(FIDO2CacheEntry cacheEntry) throws AuthenticationFailedException {

        AssertionRequest request;
        try {
            request = jsonMapper.readValue(cacheEntry.getAssertionRequest(), AssertionRequest.class);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Assertion for finish authentication flow failed due to failure " +
                    "in decoding assertion request object.", e);
        }

        return request;
    }

    private void validateFIDO2TrustedOrigin(String origin) throws FIDO2AuthenticatorClientException {

        readTrustedOrigins();
        if (!origins.contains(origin.trim())) {
            throw new FIDO2AuthenticatorClientException(FIDO2AuthenticatorConstants.INVALID_ORIGIN_MESSAGE,
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN
                            .getErrorCode());
        }
    }

    private URL getOriginUrl(String origin) throws FIDO2AuthenticatorClientException {

        URL originUrl;
        try {
            originUrl = new URL(origin);
        } catch (MalformedURLException e) {
            throw new FIDO2AuthenticatorClientException(FIDO2AuthenticatorConstants.INVALID_ORIGIN_MESSAGE,
                    FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN
                            .getErrorCode(), e);
        }

        return originUrl;
    }

    private String getTenantQualifiedUsername() {

        return UserCoreUtil.addTenantDomainToEntry(CarbonContext.getThreadLocalCarbonContext().getUsername(),
                CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
    }

}
