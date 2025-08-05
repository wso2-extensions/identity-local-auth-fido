/*
 * Copyright (c) (2019-2022), WSO2 Inc. (http://www.wso2.com).
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
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.apple.AppleAnonymousAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;
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
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.application.authenticator.fido2.dto.CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2Configuration;
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
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.MetadataService;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yubico.webauthn.data.UserVerificationRequirement.PREFERRED;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.APPLICATION_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_FINISH_REGISTRATION_INVALID_ATTESTATION;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_UPDATE_REGISTRATION_CREDENTIAL_UNAVAILABLE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.ClientExceptionErrorCodes.ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.DECODING_FAILED_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.DISPLAY_NAME_CLAIM_URL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONFIG_TRUSTED_ORIGIN_ATTRIBUTE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_CONNECTOR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO2_USER;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIRST_NAME_CLAIM_URL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.INVALID_ORIGIN_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.LAST_NAME_CLAIM_URL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.TRUSTED_ORIGINS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;

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
    private List<String> origins = null;
    private static final String userResponseTimeout = IdentityUtil.getProperty("FIDO.UserResponseTimeout");

    private static volatile WebAuthnManager webAuthnManager;
    private static volatile WebAuthnManager webAuthnManagerMDSEnabled;
    private static final Object lock = new Object();

    @Deprecated
    /** @deprecated Please use {@link #startFIDO2Registration(String)} instead. */
    public Either<String, RegistrationRequest> startRegistration(@NonNull String origin)
            throws JsonProcessingException, FIDO2AuthenticatorException {

        readTrustedOrigins();
        if (!origins.contains(origin.trim())) {
            throw new FIDO2AuthenticatorException(INVALID_ORIGIN_MESSAGE);
        }

        URL originUrl;
        try {
            originUrl = new URL(origin);
        } catch (MalformedURLException e) {
            throw new FIDO2AuthenticatorException(INVALID_ORIGIN_MESSAGE);
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
            throws JsonProcessingException, FIDO2AuthenticatorClientException, FIDO2AuthenticatorServerException {

        validateFIDO2TrustedOrigin(origin);
        URL originUrl = getOriginUrl(origin);
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        PublicKeyCredentialCreationOptions credentialCreationOptions;
        try {
            // Store the user object in a thread local property.
            IdentityUtil.threadLocalProperties.get().put(FIDO2_USER, user);
            credentialCreationOptions = relyingParty.startRegistration(buildStartRegistrationOptions(user, false));
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(FIDO2_USER);
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
            throws JsonProcessingException, FIDO2AuthenticatorClientException, FIDO2AuthenticatorServerException {

        return this.startFIDO2UsernamelessRegistration(origin, null);
    }

    public Either<String, FIDO2RegistrationRequest> startFIDO2UsernamelessRegistration(@NonNull String origin,
                                                                                       String username)
            throws JsonProcessingException, FIDO2AuthenticatorClientException, FIDO2AuthenticatorServerException {

        validateFIDO2TrustedOrigin(origin);
        URL originUrl = getOriginUrl(origin);
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        if (username == null) {
            username = getTenantQualifiedUsername();
        }

        User user = User.getUserFromUserName(username);

        PublicKeyCredentialCreationOptions credentialCreationOptions;
        try {
            // Store the user object in a thread local property.
            IdentityUtil.threadLocalProperties.get().put(FIDO2_USER, user);
            credentialCreationOptions = relyingParty.startRegistration(buildStartRegistrationOptions(user, true));
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(FIDO2_USER);
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
                log.debug(DECODING_FAILED_MESSAGE, e);
            }
            throw new FIDO2AuthenticatorException(DECODING_FAILED_MESSAGE, e);
        }

        User user = getPrivilegedUser();
        if (FIDO2DeviceStoreDAO.getInstance().getFIDO2RegistrationByUsernameAndCredentialId(user.toString(),
                response.getCredential().getId()).isPresent()) {
            throw new FIDO2AuthenticatorException("The username \"" + user + "\" is already registered.");
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(
                new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if (cacheEntry != null) {
            publicKeyCredentialCreationOptions = jsonMapper.readValue(
                    cacheEntry.getPublicKeyCredentialCreationOptions(),
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
                throw new FIDO2AuthenticatorServerException(
                        "Registration failed unexpectedly; this is likely a bug.", e);
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

        this.finishFIDO2Registration(challengeResponse, null);
    }

    public void finishFIDO2Registration(String challengeResponse, String username)
            throws FIDO2AuthenticatorServerException, FIDO2AuthenticatorClientException {

        RegistrationResponse response;
        try {
            response = jsonMapper.readValue(challengeResponse, RegistrationResponse.class);
        } catch (JsonParseException | JsonMappingException e) {
            throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                    ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode(), e);
        } catch (IOException e) {
            throw new FIDO2AuthenticatorServerException(DECODING_FAILED_MESSAGE, e);
        }

        if (username == null) {
            username = getTenantQualifiedUsername();
        }

        User user = User.getUserFromUserName(username);
        if (FIDO2DeviceStoreDAO.getInstance().getFIDO2RegistrationByUsernameAndCredentialId(user.toString(),
                response.getCredential().getId()).isPresent()) {
            throw new FIDO2AuthenticatorClientException("The username \"" + user + "\" is already registered.",
                    ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS.getErrorCode());
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance().getValueFromCacheByRequestId(
                new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if (cacheEntry != null) {
            try {
                publicKeyCredentialCreationOptions = jsonMapper.readValue(cacheEntry
                                .getPublicKeyCredentialCreationOptions(),
                        PublicKeyCredentialCreationOptions.class);
            } catch (JsonParseException | JsonMappingException e) {
                throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                        ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode(), e);
            } catch (IOException e) {
                throw new FIDO2AuthenticatorServerException(DECODING_FAILED_MESSAGE, e);
            }
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (publicKeyCredentialCreationOptions == null || relyingParty == null) {
            String message = "Registration failed! No such registration in progress";
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("Fail finishRegistration challengeResponse: {0}", challengeResponse));
            }
            throw new FIDO2AuthenticatorClientException(message, ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST
                    .getErrorCode());
        } else {
            // Perform webauthn4j attestation validations if enabled.
            if (getAuthenticatorConfigs().isAttestationValidationEnabled()) {
                Set<String> transports = response.getCredential().getResponse().getTransports().stream().map(
                        com.yubico.webauthn.data.AuthenticatorTransport::getId).collect(Collectors.toSet()
                );

                com.webauthn4j.data.RegistrationRequest registrationRequest =
                        new com.webauthn4j.data.RegistrationRequest(
                                response.getCredential().getResponse().getAttestationObject().getBytes(),
                                response.getCredential().getResponse().getClientDataJSON().getBytes(),
                                transports
                        );

                Set<Origin> originSet =
                        relyingParty.getOrigins().stream().map(Origin::new).collect(Collectors.toSet());

                List<com.webauthn4j.data.PublicKeyCredentialParameters> publicKeyCredentialParametersList =
                        relyingParty.getPreferredPubkeyParams().stream().map(pkcp ->
                                new com.webauthn4j.data.PublicKeyCredentialParameters(
                                        PublicKeyCredentialType.create(pkcp.getType().getId()),
                                        COSEAlgorithmIdentifier.create(pkcp.getAlg().getId())
                                )
                        ).collect(Collectors.toList());

                RegistrationParameters registrationParameters = new RegistrationParameters(
                        new ServerProperty(
                                originSet,
                                relyingParty.getIdentity().getId(),
                                new DefaultChallenge(response.getCredential().getResponse().getClientData()
                                        .getChallenge().getBytes()),
                                null
                        ),
                        publicKeyCredentialParametersList,
                        response.getCredential().getResponse().getAttestation().getAuthenticatorData().getFlags().UV,
                        response.getCredential().getResponse().getAttestation().getAuthenticatorData().getFlags().UP
                );

                RegistrationData registrationData;
                try {
                    registrationData = getWebAuthnManager().parse(registrationRequest);
                    getWebAuthnManager().validate(registrationData, registrationParameters);
                } catch (DataConversionException e) {
                    throw new FIDO2AuthenticatorServerException("Attestation data structure parse error", e);
                } catch (ValidationException e) {
                    throw new FIDO2AuthenticatorClientException("Validation failed: Invalid attestation!",
                            ERROR_CODE_FINISH_REGISTRATION_INVALID_ATTESTATION.getErrorCode(), e);
                } catch (MDSException e) {
                    if (!Objects.equals(e.getMessage(), "MetadataBLOB signature is invalid")) {
                        throw new FIDO2AuthenticatorClientException("Validation failed: Invalid metadata!",
                                ERROR_CODE_FINISH_REGISTRATION_INVALID_ATTESTATION.getErrorCode(), e);
                    }
                }
            }

            // Finish the registration.
            try {
                RegistrationResult registration = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                        .request(publicKeyCredentialCreationOptions)
                        .response(response.getCredential()).build()
                );

                try {
                    // Store the user object in a thread local property.
                    IdentityUtil.threadLocalProperties.get().put(FIDO2_USER, user);
                    addFIDO2Registration(publicKeyCredentialCreationOptions, response, registration);
                } finally {
                    IdentityUtil.threadLocalProperties.get().remove(FIDO2_USER);
                }

                Either.right(
                        new SuccessfulRegistrationResult(publicKeyCredentialCreationOptions, response, registration
                                .isAttestationTrusted()));
            } catch (RegistrationFailedException e) {
                throw new FIDO2AuthenticatorServerException("Registration failed!", e);
            }
        }
    }

    /**
     * Creates a FIDO2 credential registration and return it without storing it in the database.
     *
     * @param challengeResponse Challenge response.
     * @param username          Username of the user.
     * @return FIDO2 credential registration.
     * @throws FIDO2AuthenticatorServerException if an error occurs while processing the request.
     * @throws FIDO2AuthenticatorClientException if the request is invalid or if the user is already registered.
     */
    public FIDO2CredentialRegistration createFIDO2Credential(String challengeResponse,
                                                             String username)
            throws FIDO2AuthenticatorServerException, FIDO2AuthenticatorClientException {

        RegistrationResponse response;
        try {
            response = jsonMapper.readValue(challengeResponse, RegistrationResponse.class);
        } catch (JsonParseException | JsonMappingException e) {
            throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                    ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode(), e);
        } catch (IOException e) {
            throw new FIDO2AuthenticatorServerException(DECODING_FAILED_MESSAGE, e);
        }

        if (username == null) {
            username = getTenantQualifiedUsername();
        }

        User user = User.getUserFromUserName(username);
        if (FIDO2DeviceStoreDAO.getInstance().getFIDO2RegistrationByUsernameAndCredentialId(user.toString(),
                response.getCredential().getId()).isPresent()) {
            throw new FIDO2AuthenticatorClientException("The username \"" + user + "\" is already registered.",
                    ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS.getErrorCode());
        }

        String requestId = response.getRequestId().getBase64();
        FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance()
                .getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = null;
        RelyingParty relyingParty = null;
        if (cacheEntry != null) {
            try {
                publicKeyCredentialCreationOptions = jsonMapper.readValue(cacheEntry
                                .getPublicKeyCredentialCreationOptions(),
                        PublicKeyCredentialCreationOptions.class);
            } catch (JsonParseException | JsonMappingException e) {
                throw new FIDO2AuthenticatorClientException("Finish FIDO2 device registration request is invalid.",
                        ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode(), e);
            } catch (IOException e) {
                throw new FIDO2AuthenticatorServerException(DECODING_FAILED_MESSAGE, e);
            }
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
            FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));

        }
        if (publicKeyCredentialCreationOptions == null || relyingParty == null) {
            String message = "Registration failed! No such registration in progress";
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("Fail finishRegistration challengeResponse: {0}", challengeResponse));
            }
            throw new FIDO2AuthenticatorClientException(message,
                    ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST.getErrorCode());
        } else {
            if (getAuthenticatorConfigs().isAttestationValidationEnabled()) {
                Set<String> transports = response.getCredential().getResponse().getTransports().stream().map(
                        com.yubico.webauthn.data.AuthenticatorTransport::getId).collect(Collectors.toSet()
                );

                com.webauthn4j.data.RegistrationRequest registrationRequest =
                        new com.webauthn4j.data.RegistrationRequest(
                                response.getCredential().getResponse().getAttestationObject().getBytes(),
                                response.getCredential().getResponse().getClientDataJSON().getBytes(),
                                transports
                        );

                Set<Origin> originSet =
                        relyingParty.getOrigins().stream().map(Origin::new).collect(Collectors.toSet());

                List<com.webauthn4j.data.PublicKeyCredentialParameters> publicKeyCredentialParametersList =
                        relyingParty.getPreferredPubkeyParams().stream().map(pkcp ->
                                new com.webauthn4j.data.PublicKeyCredentialParameters(
                                        PublicKeyCredentialType.create(pkcp.getType().getId()),
                                        COSEAlgorithmIdentifier.create(pkcp.getAlg().getId())
                                )
                        ).collect(Collectors.toList());

                RegistrationParameters registrationParameters = new RegistrationParameters(
                        new ServerProperty(
                                originSet,
                                relyingParty.getIdentity().getId(),
                                new DefaultChallenge(response.getCredential().getResponse().getClientData()
                                        .getChallenge().getBytes()),
                                null
                        ),
                        publicKeyCredentialParametersList,
                        response.getCredential().getResponse().getAttestation().getAuthenticatorData().getFlags().UV,
                        response.getCredential().getResponse().getAttestation().getAuthenticatorData().getFlags().UP
                );

                RegistrationData registrationData;
                try {
                    registrationData = getWebAuthnManager().parse(registrationRequest);
                    getWebAuthnManager().validate(registrationData, registrationParameters);
                } catch (DataConversionException e) {
                    throw new FIDO2AuthenticatorServerException("Attestation data structure parse error", e);
                } catch (ValidationException e) {
                    throw new FIDO2AuthenticatorClientException("Validation failed: Invalid attestation!",
                            ERROR_CODE_FINISH_REGISTRATION_INVALID_ATTESTATION.getErrorCode(), e);
                } catch (MDSException e) {
                    if (!Objects.equals(e.getMessage(), "MetadataBLOB signature is invalid")) {
                        throw new FIDO2AuthenticatorClientException("Validation failed: Invalid metadata!",
                                ERROR_CODE_FINISH_REGISTRATION_INVALID_ATTESTATION.getErrorCode(), e);
                    }
                }
            }

            RegistrationResult registration;
            try {
                registration = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                        .request(publicKeyCredentialCreationOptions)
                        .response(response.getCredential()).build()
                );
            } catch (RegistrationFailedException e) {
                throw new FIDO2AuthenticatorServerException("Registration failed!", e);
            }

            UserIdentity userIdentity = publicKeyCredentialCreationOptions.getUser();
            RegisteredCredential credential = RegisteredCredential.builder()
                    .credentialId(registration.getKeyId().getId())
                    .userHandle(userIdentity.getId())
                    .publicKeyCose(registration.getPublicKeyCose())
                    .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                            .getSignatureCounter())
                    .build();

            boolean requireResidentKey = false;
            if ((publicKeyCredentialCreationOptions.getAuthenticatorSelection().isPresent()) &&
                    (publicKeyCredentialCreationOptions.getAuthenticatorSelection().get().getResidentKey().isPresent()) &&
                    (publicKeyCredentialCreationOptions.getAuthenticatorSelection().get().getResidentKey().get()) ==
                            ResidentKeyRequirement.REQUIRED) {
                requireResidentKey = true;
            }

            return FIDO2CredentialRegistration.builder()
                    .userIdentity(userIdentity)
                    .registrationTime(clock.instant())
                    .credential(credential)
                    .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                            .getSignatureCounter())
                    .displayName(null)
                    .isUsernamelessSupported(requireResidentKey)
                    .build();
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
            if (userStorage.getFIDO2RegistrationsByUser(user).isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No registered device found for user :" + user.toString());
                }
                return null;
            } else {
                RelyingParty relyingParty = buildRelyingParty(originUrl);
                AssertionRequestWrapper request = new AssertionRequestWrapper(
                        generateRandom(),
                        relyingParty.startAssertion(StartAssertionOptions.builder().username(user.toString()).build())
                );
                FIDO2Cache.getInstance().addToCacheByRequestWrapperId(
                        new FIDO2CacheKey(request.getRequestId().getBase64()),
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
            FIDO2Cache.getInstance().addToCacheByRequestWrapperId(
                    new FIDO2CacheKey(request.getRequestId().getBase64()),
                    new FIDO2CacheEntry(null, jsonMapper.writeValueAsString(request
                            .getRequest()), originUrl)
            );
            return FIDOUtil.writeJson(request);
        } catch (MalformedURLException | JsonProcessingException | FIDO2AuthenticatorServerException e) {
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

        /**
         * Check if the responseJson is having the id field defined.
         * This check should be performed according to the fido compliance test cases.
         */
        if (!responseJson.contains("\"id\"")) {
            throw new AuthenticationFailedException("Assertion for finish authentication flow failed due to id not " +
                    "found in json response: " + responseJson);
        }

        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
            String requestId = response.getRequestId().getBase64();
            FIDO2CacheEntry cacheEntry = FIDO2Cache.getInstance()
                    .getValueFromCacheByRequestId(new FIDO2CacheKey(requestId));

            if (cacheEntry != null) {
                request = jsonMapper.readValue(cacheEntry.getAssertionRequest(), AssertionRequest.class);
                relyingParty = buildRelyingParty(cacheEntry.getOrigin());
                FIDO2Cache.getInstance().clearCacheEntryByRequestId(new FIDO2CacheKey(requestId));
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Assertion failed! Failed to decode response object.", e);
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException("Server error when building relying party for authentication.", e);
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
                            .getFIDO2RegistrationsByUsername(result.getUsername()), null);
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
        RelyingParty relyingParty = null;
        try {
            relyingParty = buildRelyingParty(cacheEntry.getOrigin());
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException("Server error when building relying party for request ID: ",
                    requestId, e);
        }
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
                        userStorage.getFIDO2RegistrationsByUser(authenticatedUser), null);
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

        return userStorage.getFIDO2RegistrationsByUsername(username);
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
        Optional<CredentialRegistration> credReg = userStorage.getRegistrationByUsernameAndCredentialId(
                user.toString(), identifier);

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
                    ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("Credential ID is not valid Base64Url data: " + credentialId,
                    ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        Optional<FIDO2CredentialRegistration> credReg = userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user
                .toString(), identifier);

        if (credReg.isPresent()) {
            userStorage.removeFIDO2RegistrationByUsername(user.toString(), credReg.get());
        } else {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
        }
    }

    /**
     * Removes the FIDO2 device registration via the credential ID and username.
     *
     * @param credentialId Credential ID.
     * @param username     Username of the user who registered the credential.
     * @throws FIDO2AuthenticatorServerException if an error occurs in the server.
     * @throws FIDO2AuthenticatorClientException if an error occurs from the client.
     */
    public void deregisterFIDO2Credential(String credentialId, String username)
            throws FIDO2AuthenticatorServerException, FIDO2AuthenticatorClientException {

        if (StringUtils.isBlank(credentialId)) {
            throw new FIDO2AuthenticatorClientException("Credential ID must not be empty.",
                    ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("Credential ID is not valid Base64Url data: " + credentialId,
                    ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(username);
        Optional<FIDO2CredentialRegistration> credReg = userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user
                .toString(), identifier);

        if (credReg.isPresent()) {
            userStorage.removeFIDO2RegistrationByUsername(user.toString(), credReg.get());
        } else {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
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
                    ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("The Credential ID: " + credentialId + " is not a valid " +
                    "Base64Url data.", ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        Optional<FIDO2CredentialRegistration> credentialRegistration =
                userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user.toString(), identifier);

        if (!credentialRegistration.isPresent()) {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    ERROR_CODE_UPDATE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
        }
        userStorage.updateFIDO2DeviceDisplayName(user, credentialRegistration.get(), newDisplayName);
    }

    public void updateFIDO2DeviceDisplayName(String credentialId, String newDisplayName, String username)
            throws FIDO2AuthenticatorClientException, FIDO2AuthenticatorServerException {

        if (StringUtils.isBlank(credentialId)) {
            throw new FIDO2AuthenticatorClientException("Credential ID must not be empty.",
                    ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode());
        }

        final ByteArray identifier;
        try {
            identifier = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            throw new FIDO2AuthenticatorClientException("The Credential ID: " + credentialId + " is not a valid " +
                    "Base64Url data.", ERROR_CODE_UPDATE_REGISTRATION_INVALID_CREDENTIAL.getErrorCode(), e);
        }

        User user = User.getUserFromUserName(username);
        Optional<FIDO2CredentialRegistration> credentialRegistration =
                userStorage.getFIDO2RegistrationByUsernameAndCredentialId(user.toString(), identifier);

        if (!credentialRegistration.isPresent()) {
            throw new FIDO2AuthenticatorClientException("Credential ID not registered: " + credentialId,
                    ERROR_CODE_UPDATE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getErrorCode());
        }
        userStorage.updateFIDO2DeviceDisplayName(user, credentialRegistration.get(), newDisplayName);
    }

    /**
     * Initiate FIDO2 registration flow.
     *
     * @param origin      FIDO2 trusted origin.
     * @param username    Username of the user to be registered.
     * @param displayName Display name of the user to be registered.
     * @return FIDO2 registration request.
     * @throws JsonProcessingException           if an error occurs while processing JSON.
     * @throws FIDO2AuthenticatorServerException if an error occurs in the server.
     * @throws FIDO2AuthenticatorClientException if an error occurs in the client.
     */
    public Either<String, FIDO2RegistrationRequest> initiateFIDO2Registration(String origin, String username,
                                                                              String displayName)
            throws JsonProcessingException, FIDO2AuthenticatorServerException, FIDO2AuthenticatorClientException {

        validateFIDO2TrustedOrigin(origin);

        User user = User.getUserFromUserName(UserCoreUtil.addTenantDomainToEntry(username,
                CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
        URL originUrl = getOriginUrl(origin);
        RelyingParty relyingParty = buildRelyingParty(originUrl);

        PublicKeyCredentialCreationOptions options;
        try {
            IdentityUtil.threadLocalProperties.get().put(FIDO2_USER, user);
            options = relyingParty.startRegistration(buildStartRegistrationOptions(user, displayName, false));
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(FIDO2_USER);
        }

        ByteArray requestId = generateRandom();
        FIDO2RegistrationRequest request = new FIDO2RegistrationRequest(requestId, options);

        FIDO2Cache.getInstance().addToCacheByRequestId(
                new FIDO2CacheKey(requestId.getBase64()),
                new FIDO2CacheEntry(jsonMapper.writeValueAsString(options), null, originUrl)
        );

        return Either.right(request);
    }

    private RelyingParty buildRelyingParty(URL originUrl) throws FIDO2AuthenticatorServerException {

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

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder().id(rpId).name(APPLICATION_NAME).build();

        List<PublicKeyCredentialParameters> preferredPublicKeyCredentialParameters = Collections.unmodifiableList(
                Arrays.asList(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.EdDSA,
                        PublicKeyCredentialParameters.RS1, PublicKeyCredentialParameters.RS256)
        );

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(userStorage)
                .origins(new HashSet<String>(origins))
                .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
                .preferredPubkeyParams(preferredPublicKeyCredentialParameters)
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
        if ((publicKeyCredentialCreationOptions.getAuthenticatorSelection().isPresent()) &&
                (publicKeyCredentialCreationOptions.getAuthenticatorSelection().get().getResidentKey().isPresent()) &&
                (publicKeyCredentialCreationOptions.getAuthenticatorSelection().get().getResidentKey().get()) ==
                        ResidentKeyRequirement.REQUIRED) {
            requireResidentKey = true;
        }

        FIDO2CredentialRegistration reg = FIDO2CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .registrationTime(clock.instant())
                .credential(credential)
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData()
                        .getSignatureCounter())
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

    private StartRegistrationOptions buildStartRegistrationOptions(User user, boolean requireResidentKey)
            throws FIDO2AuthenticatorClientException {

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

    private StartRegistrationOptions buildStartRegistrationOptions(User user, String displayName,
                                                                   Boolean requireResidentKey) {

        return StartRegistrationOptions.builder()
                .user(buildUserIdentity(user, displayName))
                .timeout(Integer.parseInt(userResponseTimeout))
                .authenticatorSelection(buildAuthenticatorSelection(requireResidentKey))
                .extensions(RegistrationExtensionInputs.builder().build())
                .build();
    }

    private AuthenticatorSelectionCriteria buildAuthenticatorSelection(boolean requireResidentKey) {

        if (requireResidentKey) {
            return AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.REQUIRED)
                    .userVerification(PREFERRED).build();
        }
        return AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.DISCOURAGED)
                .userVerification(PREFERRED).build();
    }

    private String getUserDisplayName(User user) throws FIDO2AuthenticatorServerException {

        String displayName;
        displayName = getUserClaimValue(user, DISPLAY_NAME_CLAIM_URL);
        // If the displayName is not available, build the displayName with firstName and lastName.
        if (StringUtils.isBlank(displayName)) {
            String firstName = getUserClaimValue(user, FIRST_NAME_CLAIM_URL);
            String lastName = getUserClaimValue(user, LAST_NAME_CLAIM_URL);
            if (StringUtils.isNotBlank(firstName) || StringUtils.isNotBlank(lastName)) {
                displayName = StringUtils.join(new String[]{firstName, lastName}, " ");
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

        ByteArray userHandle = FIDO2DeviceStoreDAO.getInstance().getUserHandleForUsername(user.toString())
                .orElseGet(WebAuthnService::generateRandom);
        return UserIdentity.builder().name(user.getUserName()).displayName(getUserDisplayName(user))
                .id(userHandle).build();
    }

    private UserIdentity buildUserIdentity(User user, String displayName) {

        ByteArray userHandle = userStorage.getUserHandleForUsername(user.toString())
                .orElseGet(WebAuthnService::generateRandom);
        return UserIdentity.builder()
                .name(user.getUserName())
                .displayName(displayName)
                .id(userHandle)
                .build();
    }

    private User getPrivilegedUser() {

        User user = User.getUserFromUserName(getTenantQualifiedUsername());
        return user;
    }

    private void readTrustedOrigins() throws FIDO2AuthenticatorServerException {

        origins = new ArrayList<>();
        String[] trustedOriginsFromDB = null;
        try {
            trustedOriginsFromDB = getFIDO2TrustedOrigins();
        } catch (FIDO2AuthenticatorServerException e) {
            throw new FIDO2AuthenticatorServerException("Error when retrieving trusted origins from DB.", e);
        }
        if (trustedOriginsFromDB != null) {
            origins.addAll(Arrays.asList(trustedOriginsFromDB));
        }
        Object value = IdentityConfigParser.getInstance().getConfiguration().get(TRUSTED_ORIGINS);
        if (value instanceof ArrayList) {
            origins.addAll((ArrayList) value);
        } else if (value instanceof String) {
            origins.add((String) value);
        }
        origins.replaceAll(IdentityUtil::fillURLPlaceholders);

        /*
         * Process the list of origins to ensure all variations are covered:
         * 1. For each origin, remove the default ports (443 for HTTPS and 80 for HTTP) if they are explicitly
         *    specified.
         * 2. Then, for each origin, add variations with the default ports explicitly appended.
         * 3. This ensures that the list contains both versions of each origin (with and without default ports),
         *    accommodating scenarios where the default port might be omitted or explicitly included in the origin
         * string.
         */
        List<String> updatedOrigins = origins.stream()
                .flatMap(url -> Stream.of(removeDefaultPort(url), appendDefaultPortIfAbsent(url))).distinct()
                .collect(Collectors.toList());

        origins.clear();
        origins.addAll(updatedOrigins);
    }

    private String removeDefaultPort(String url) {

        return url.replaceAll(":(443|80)(/|$)", "$2");
    }

    private String appendDefaultPortIfAbsent(String url) {

        if (url.matches("^https://[^/:]+($|/)")) {
            return url + ":443";
        } else if (url.matches("^http://[^/:]+($|/)")) {
            return url + ":80";
        }
        return url;
    }

    private AssertionResult getAssertionResult(AssertionRequest request, AssertionResponse response,
                                               RelyingParty relyingParty) throws AuthenticationFailedException {

        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    getPublicKeyCredential(response);

            return relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request).response(credential).build());
        } catch (AssertionFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Assertion failure exception.", e);
            }
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

        /**
         * Check if the responseJson is having the id field defined.
         * This check should be performed according to the fido compliance test cases.
         */
        if (!responseJson.contains("\"id\"")) {
            throw new AuthenticationFailedException("Assertion for finish authentication flow failed due to id not " +
                    "found in json response: " + responseJson);
        }

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

    private void validateFIDO2TrustedOrigin(String origin) throws FIDO2AuthenticatorClientException,
            FIDO2AuthenticatorServerException {

        readTrustedOrigins();
        if (!origins.contains(origin.trim())) {
            throw new FIDO2AuthenticatorClientException(INVALID_ORIGIN_MESSAGE,
                    ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN.getErrorCode());
        }
    }

    private URL getOriginUrl(String origin) throws FIDO2AuthenticatorClientException {

        URL originUrl;
        try {
            originUrl = new URL(origin);
        } catch (MalformedURLException e) {
            throw new FIDO2AuthenticatorClientException(INVALID_ORIGIN_MESSAGE,
                    ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN.getErrorCode(), e);
        }

        return originUrl;
    }

    private String getTenantQualifiedUsername() {

        return UserCoreUtil.addTenantDomainToEntry(CarbonContext.getThreadLocalCarbonContext().getUsername(),
                CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
    }

    private WebAuthnManager getWebAuthnManager() throws FIDO2AuthenticatorServerException {

        if (FIDOUtil.isMetadataValidationsEnabled() && getAuthenticatorConfigs().isMdsValidationEnabled()) {
            if (webAuthnManagerMDSEnabled == null) {
                synchronized (lock) {
                    if (webAuthnManagerMDSEnabled == null) {
                        MetadataService metadataService = FIDO2AuthenticatorServiceDataHolder.getInstance()
                                .getMetadataService();
                        if (metadataService.getDefaultCertPathTrustworthinessValidator() == null) {
                            log.info("FIDO2 mds certificate trustworthiness validator is null. " +
                                    "Hence initializing...");
                            metadataService.initializeDefaultCertPathTrustworthinessValidator();
                        }
                        CertPathTrustworthinessValidator certPathTrustworthinessValidator = metadataService
                                .getDefaultCertPathTrustworthinessValidator();

                        webAuthnManagerMDSEnabled = new WebAuthnManager(
                                Arrays.asList(
                                        new PackedAttestationStatementValidator(),
                                        new FIDOU2FAttestationStatementValidator(),
                                        new AndroidKeyAttestationStatementValidator(),
                                        new AndroidSafetyNetAttestationStatementValidator(),
                                        new TPMAttestationStatementValidator(),
                                        new AppleAnonymousAttestationStatementValidator(),
                                        new NoneAttestationStatementValidator()
                                ),
                                certPathTrustworthinessValidator,
                                new DefaultSelfAttestationTrustworthinessValidator()
                        );
                    }
                }
            }

            return webAuthnManagerMDSEnabled;
        } else {
            if (webAuthnManager == null) {
                synchronized (lock) {
                    if (webAuthnManager == null) {
                        webAuthnManager = new WebAuthnManager(
                                Arrays.asList(
                                        new PackedAttestationStatementValidator(),
                                        new FIDOU2FAttestationStatementValidator(),
                                        new AndroidKeyAttestationStatementValidator(),
                                        new AndroidSafetyNetAttestationStatementValidator(),
                                        new TPMAttestationStatementValidator(),
                                        new AppleAnonymousAttestationStatementValidator(),
                                        new NoneAttestationStatementValidator()
                                ),
                                new NullCertPathTrustworthinessValidator(),
                                new DefaultSelfAttestationTrustworthinessValidator()
                        );
                    }
                }
            }

            return webAuthnManager;
        }
    }

    private FIDO2Configuration getAuthenticatorConfigs() throws FIDO2AuthenticatorServerException {

        boolean attestationValidationEnabled;
        boolean mdsValidationEnabled;

        try {
            attestationValidationEnabled = Boolean.parseBoolean(FIDO2AuthenticatorServiceDataHolder.getInstance()
                    .getConfigurationManager().getAttribute(FIDO_CONFIG_RESOURCE_TYPE_NAME, FIDO2_CONFIG_RESOURCE_NAME,
                            FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME).getValue()
            );
        } catch (ConfigurationManagementException e) {
            if (Objects.equals(e.getErrorCode(), ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME
                            + " attribute doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value of "
                            + FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE + ".");
                }
                attestationValidationEnabled = FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE;
            } else if (Objects.equals(e.getErrorCode(), ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONFIG_RESOURCE_NAME + " resource doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value for the attribute: "
                            + FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME + ", value: "
                            + FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE + ".");
                }
                attestationValidationEnabled = FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE;
            } else {
                throw new FIDO2AuthenticatorServerException("Error in retrieving "
                        + FIDO2_CONFIG_ATTESTATION_VALIDATION_ATTRIBUTE_NAME + " configuration for the tenant: "
                        + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(), e);
            }
        }

        try {
            mdsValidationEnabled = Boolean.parseBoolean(FIDO2AuthenticatorServiceDataHolder.getInstance()
                    .getConfigurationManager().getAttribute(FIDO_CONFIG_RESOURCE_TYPE_NAME, FIDO2_CONFIG_RESOURCE_NAME,
                            FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME).getValue()
            );
        } catch (ConfigurationManagementException e) {
            if (Objects.equals(e.getErrorCode(), ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME
                            + " attribute doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value of "
                            + FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE + ".");
                }
                mdsValidationEnabled = FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE;
            } else if (Objects.equals(e.getErrorCode(), ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONFIG_RESOURCE_NAME + " resource doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value for the attribute: "
                            + FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME + ", value: "
                            + FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE + ".");
                }
                mdsValidationEnabled = FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE;
            } else {
                throw new FIDO2AuthenticatorServerException("Error in retrieving "
                        + FIDO2_CONFIG_MDS_VALIDATION_ATTRIBUTE_NAME + " configuration for the tenant: "
                        + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(), e);
            }
        }

        return new FIDO2Configuration(attestationValidationEnabled, mdsValidationEnabled);
    }

    private String[] getFIDO2TrustedOrigins() throws FIDO2AuthenticatorServerException {

        String[] fidoTrustedOrigins = null;
        try {
            String trustedOriginsFromDB = FIDO2AuthenticatorServiceDataHolder.getInstance().getConfigurationManager()
                    .getAttribute(FIDO_CONFIG_RESOURCE_TYPE_NAME, FIDO2_CONNECTOR_CONFIG_RESOURCE_NAME,
                            FIDO2_CONFIG_TRUSTED_ORIGIN_ATTRIBUTE_NAME).getValue();
            if (StringUtils.isNotBlank(trustedOriginsFromDB)) {
                fidoTrustedOrigins = trustedOriginsFromDB.split(",");
            }
        } catch (ConfigurationManagementException e) {
            if (Objects.equals(e.getErrorCode(), ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONFIG_TRUSTED_ORIGIN_ATTRIBUTE_NAME
                            + " attribute doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value from files.");
                }
            } else if (Objects.equals(e.getErrorCode(), ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug(FIDO2_CONNECTOR_CONFIG_RESOURCE_NAME + " resource doesn't exist for the tenant: "
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId()
                            + ". Using the default configuration value from files for the attribute: "
                            + FIDO2_CONFIG_TRUSTED_ORIGIN_ATTRIBUTE_NAME + ".");
                }
            } else {
                throw new FIDO2AuthenticatorServerException("Error in retrieving "
                        + FIDO2_CONFIG_TRUSTED_ORIGIN_ATTRIBUTE_NAME + " configuration for the tenant: "
                        + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(), e);
            }
        }
        return fidoTrustedOrigins;
    }

    public boolean isFidoKeyRegistered(String username) throws AuthenticationFailedException {

        try {
            return !userStorage.getFIDO2RegistrationsByUsername(username).isEmpty();
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }
    }

    public boolean isFidoKeyRegistered(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        try {
            return !userStorage.getFIDO2RegistrationsByUser(authenticatedUser).isEmpty();
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }
    }
}
