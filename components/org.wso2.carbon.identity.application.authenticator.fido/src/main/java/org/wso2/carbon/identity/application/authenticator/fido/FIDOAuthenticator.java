/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.fido;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.AUTHENTICATOR_FIDO;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.CHALLENGE_DATA;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.CHALLENGE_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.ConnectorConfig;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.ERROR_CODE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.FIDO_KEY_CREDENTIAL;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.FIDO_KEY_DISPLAY_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.FIDO_KEY_ID;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.IS_PASSKEY_CREATION_CONSENT_RECEIVED;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.ActionIDs.VALIDATE_FIDO_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.FIDO_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.SCENARIO;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.ScenarioTypes;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.TOKEN_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.USER_NAME;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil.writeJson;

/**
 * FIDO U2F Specification based authenticator.
 */
public class FIDOAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(FIDOAuthenticator.class);

    private static FIDOAuthenticator instance = new FIDOAuthenticator();

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // If the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // If an authentication complete request comes go through this flow.
        if (StringUtils.isNotEmpty(request.getParameter(TOKEN_RESPONSE)) &&
                !(StringUtils.isNotEmpty(request.getParameter(SCENARIO)) &&
                        ScenarioTypes.INIT_FIDO_ENROLL.equals(request.getParameter(SCENARIO)))) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // If an authentication flow cancellation request received from the user, go through this flow.
        if (StringUtils.isNotEmpty(request.getParameter(SCENARIO)) &&
                        ScenarioTypes.CANCEL_FIDO_AUTH.equals(request.getParameter(SCENARIO))) {
            return AuthenticatorFlowStatus.FAIL_COMPLETED;
        }

        // Extract the configurations
        boolean enablePasskeyProgressiveEnrollment = isPasskeyProgressiveEnrollmentEnabled(context.getTenantDomain());
        boolean enableUsernamelessAuthentication = isUsernamelessAuthenticationEnabled(context.getTenantDomain());
        addPasskeyEnrollmentConfigToEndpointParams(context, enablePasskeyProgressiveEnrollment);

        // If a passkey enrollment request comes set a property to the context mentioning the user consent is received.
        if (enablePasskeyProgressiveEnrollment && !StringUtils.isEmpty(request.getParameter(SCENARIO)) &&
                ScenarioTypes.INIT_FIDO_ENROLL.equals(request.getParameter(SCENARIO))) {
            context.setProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED, true);
        }

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);

        if (authenticatedUser != null) {

            // We need to identify the username that the server is using to identify the user. This is needed to handle
            // federated scenarios, since for federated users, the username in the authentication context is not same
            // as the username when the user is provisioned to the server.
            String mappedLocalUsername = getMappedLocalUsername(authenticatedUser, context);
            if (StringUtils.isBlank(mappedLocalUsername)) {
                // If the mappedLocalUsername is blank, that means this is an initial login attempt by an unprovisioned
                // federated user.
                handleUnProvisionedFederatedUser(response);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            boolean enrolledPasskeysExist = hasUserSetPasskeys(mappedLocalUsername);
            if (enrolledPasskeysExist) {
                // If the user have already enrolled passkeys and if the user initiated a passkey enrollment request,
                // then inform the user that passkeys already exist and disregard the enrollment request.
                if (isPasskeyCreationConsentReceived(context)) {
                    redirectToPasskeysExistenceStatusPage(response, context, true);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
                // If the user has at least one enrolled passkey, then initiate the authentication flow.
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                if (enablePasskeyProgressiveEnrollment) {
                    // If the user hasn't enrolled passkeys and if the passkey enrollment consent hasn't
                    // received, then redirect the user to the consent page prior to initiating the passkey
                    // enrollment request.
                    if (!isPasskeyCreationConsentReceived(context)) {
                        redirectToPasskeyEnrollmentConsentPage(response, context);
                        return AuthenticatorFlowStatus.INCOMPLETE;
                    }
                    if (!FrameworkUtils.isPreviousIdPAuthenticationFlowHandler(context)) {
                        return handlePasskeyEnrollmentScenarios(request, response, context);
                    } else {
                        persistUsername(context, authenticatedUser.getUserName());
                        context.setProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED, true);
                        return AuthenticatorFlowStatus.FAIL_COMPLETED;
                    }
                } else {
                    // If passkeyProgressiveEnrollment is turned off, redirect users to the passkey status page to
                    // inform them that they have no registered passkeys and can enroll through myAccount.
                    redirectToPasskeysExistenceStatusPage(response, context, false);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            }
        } else {

            if (enablePasskeyProgressiveEnrollment && isPasskeyCreationConsentReceived(context)) {
                if (!StringUtils.isEmpty(request.getParameter(USER_NAME))) {
                    persistUsername(context, request.getParameter(USER_NAME));
                }
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }

            if (isFidoAsFirstFactor(context)) {

                if (enableUsernamelessAuthentication) {
                    initiateAuthenticationRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }

                if (StringUtils.isEmpty(request.getParameter(USER_NAME))) {
                    redirectToFIDOIdentifierFirstPage(response, context);
                    context.setProperty(FIDOAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }

                // If an authentication request initiated from the custom FIDO identifier page, go through this flow.
                if (!StringUtils.isEmpty(request.getParameter(SCENARIO)) &&
                        ScenarioTypes.INIT_FIDO_AUTH.equals(request.getParameter(SCENARIO))) {
                    persistUsername(context, request.getParameter(USER_NAME));
                    initiateAuthenticationRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            }
            log.debug("The user does not exist in the user stores.");
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    private static boolean isPasskeyCreationConsentReceived(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED));
    }

    private AuthenticatorFlowStatus handlePasskeyEnrollmentScenarios(HttpServletRequest request,
                                                                     HttpServletResponse response,
                                                                     AuthenticationContext context)
            throws AuthenticationFailedException {

        if (StringUtils.isNotBlank(request.getParameter(SCENARIO))) {
            String scenario = request.getParameter(SCENARIO);
            switch (scenario) {
                case ScenarioTypes.INIT_FIDO_ENROLL:
                    // Redirect the user in this flow upon user initiating the passkey enrollment request
                    initiatePasskeyEnrollmentRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                case ScenarioTypes.FINISH_FIDO_ENROLL:
                    // Redirect the user in this flow upon user requesting to finish the passkey enrollment
                    processPasskeyEnrollmentResponse(request, response, context);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                case ScenarioTypes.CANCEL_FIDO_ENROLL:
                    // Redirect the user in this flow upon user cancelling the passkey enrollment
                    processPasskeyEnrollmentResponse(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }
        initiatePasskeyEnrollmentRequest(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    private void redirectToFIDOIdentifierFirstPage(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String identifierAuthPageURL = getFIDOIdentifierFirstPageURL(context);
            response.sendRedirect(identifierAuthPageURL);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate FIDO identifier retrieving request", e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building FIDO identifier retrieving page URL.", e);
        }
    }

    private void redirectToPasskeyEnrollmentConsentPage(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Passkey enrollment failed!. Cannot proceed further without " +
                    "identifying the user");
        }

        try {
            String passkeyEnrollmentConsentPageURL = getPasskeysEnrollmentStatusRedirectUrl(context, false);
            response.sendRedirect(passkeyEnrollmentConsentPageURL);
            context.setProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED, true);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate passkey enrollment consent retrieving request",
                    user, e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building passkey enrollment consent redirect URL.", e);
        }
    }

    private void redirectToPasskeysExistenceStatusPage(HttpServletResponse response, AuthenticationContext context,
                                                       boolean isPasskeysExist) throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Passkeys existence status display failed!. Cannot redirect the " +
                    "user to the passkeys existence status display page without identifying the user.");
        }
        try {
            String passkeysExistenceStatusDisplayRedirectUrl =
                    getPasskeysEnrollmentStatusRedirectUrl(context, isPasskeysExist);
            response.sendRedirect(passkeysExistenceStatusDisplayRedirectUrl);
            context.setProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED, false);
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    "Could not redirect the user to passkeys existence status display page", e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building passkeys existence status display page URL.",
                    e);
        }
    }

    private void initiatePasskeyEnrollmentRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Passkey enrollment failed!. Cannot proceed further without " +
                    "identifying the user");
        }

        //If the user is federated, retrieve the just-in-time provisioned federated user.
        if ((user != null) && user.isFederatedUser()) {
            AuthenticatedUser provisionedFederateUser = getProvisionedFederatedUser(user, context);
            if (provisionedFederateUser == null) {
                // If the provisionedFederateUser is blank, that means this is a login attempt by an unprovisioned
                // federated user.
                handleUnProvisionedFederatedUser(response);
            }
            user = provisionedFederateUser;
        }

        // Retrieving AppID
        // Origin as appID eg: https://example.com:8080
        String appID = resolveAppId(request);

        try {
            String passkeyEnrollmentRedirectUrl = getPasskeyEnrollmentRedirectUrl(appID, user, context);
            response.sendRedirect(passkeyEnrollmentRedirectUrl);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate passkey enrollment request", user, e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building passkey enrollment redirection URL.", e);
        }
    }

    private String getPasskeyEnrollmentRedirectUrl(String appID, AuthenticatedUser user, AuthenticationContext context)
            throws AuthenticationFailedException, UnsupportedEncodingException, URLBuilderException,
            URISyntaxException {

        String data = initiateFido2PasskeyEnrollmentRequest(appID, user);
        String urlEncodedData =
                StringUtils.isNotBlank(data) ? URLEncoder.encode(data, IdentityCoreConstants.UTF_8) : null;

        String passkeyEnrollmentPageURL =
                getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_ENROLL);
        if (StringUtils.isBlank(passkeyEnrollmentPageURL)) {
            passkeyEnrollmentPageURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_ENROLL);
        }
        passkeyEnrollmentPageURL = passkeyEnrollmentPageURL + ("?") + "&authenticators=" + getName() + ":" + "LOCAL" +
                "&type=fido&sessionDataKey=" + context.getContextIdentifier() + "&data=" + urlEncodedData;

        return buildAbsoluteURL(passkeyEnrollmentPageURL);
    }

    private String getPasskeysEnrollmentStatusRedirectUrl(AuthenticationContext context, boolean isKeyExist)
            throws URLBuilderException, URISyntaxException {

        String passkeysEnrollmentStatusRedirectUrl;

        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO2_PASSKEY_STATUS))) {
            passkeysEnrollmentStatusRedirectUrl =
                    getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_PASSKEY_STATUS);
        } else {
            passkeysEnrollmentStatusRedirectUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_PASSKEY_STATUS);
        }

        passkeysEnrollmentStatusRedirectUrl = passkeysEnrollmentStatusRedirectUrl + ("?") + "&authenticators=" +
                getName() + ":" + "LOCAL" + "&type=fido&sessionDataKey=" + context.getContextIdentifier() +
                "&keyExist=" + isKeyExist;

        return buildAbsoluteURL(passkeysEnrollmentStatusRedirectUrl);
    }

    private String getFIDOIdentifierFirstPageURL(AuthenticationContext context)
            throws URLBuilderException, URISyntaxException {

        String fidoIdentifierAuthPageURL;

        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO2_IDENTIFIER_FIRST))) {
            fidoIdentifierAuthPageURL =
                    getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_IDENTIFIER_FIRST);
        } else {
            fidoIdentifierAuthPageURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace(
                    FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_IDENTIFIER_FIRST);
        }

        fidoIdentifierAuthPageURL = fidoIdentifierAuthPageURL + ("?") + "&authenticators=" + getName() + ":" +
                "LOCAL" + "&type=fido&sessionDataKey=" + context.getContextIdentifier();

        return buildAbsoluteURL(fidoIdentifierAuthPageURL);
    }

    protected void processPasskeyEnrollmentResponse(HttpServletRequest request, HttpServletResponse response,
                                                    AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Passkey enrollment failed! Cannot proceed further without " +
                    "identifying the user");
        }
        //If the user is federated, retrieve the just-in-time provisioned federated user.
        if (user.isFederatedUser()) {
            AuthenticatedUser provisionedFederateUser = getProvisionedFederatedUser(user, context);
            if (provisionedFederateUser == null) {
                // If the provisionedFederateUser is blank, that means this is a login attempt by an unprovisioned
                // federated user.
                handleUnProvisionedFederatedUser(response);
            }
            user = provisionedFederateUser;
        }

        String challengeResponse = request.getParameter(CHALLENGE_RESPONSE);
        String displayName = request.getParameter(FIDO_KEY_DISPLAY_NAME);

        if (challengeResponse != null && !challengeResponse.contains(ERROR_CODE)) {

            processFido2PasskeyEnrollmentResponse(challengeResponse, user.getUserName());

            // Parse the JSON string into a JSONObject
            JSONObject json = new JSONObject(challengeResponse);

            // Extract the "credential" object
            JSONObject credentialObject = json.getJSONObject(FIDO_KEY_CREDENTIAL);

            // Extract the "id" from the "credential" object
            String credentialId = credentialObject.getString(FIDO_KEY_ID);

            // Set the key name
            setPasskeyDisplayName(credentialId, displayName, user.getUserName());

            context.setSubject(user);
            context.setProperty(IS_PASSKEY_CREATION_CONSENT_RECEIVED, false);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Passkey enrollment failed: " + challengeResponse);
            }
            throw new InvalidCredentialsException("Passkey enrollment failed: ", getMaskedUsername(user.getUserName()));
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    FIDO_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing FIDO authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        AuthenticatedUser user = getUsername(context);
        //If the user is federated, retrieve the just-in-time provisioned federated user.
        if ((user != null) && user.isFederatedUser()) {
            AuthenticatedUser provisionedFederateUser = getProvisionedFederatedUser(user, context);
            if (provisionedFederateUser == null) {
                // If the provisionedFederateUser is blank, that means this is a login attempt by an unprovisioned
                // federated user.
                handleUnProvisionedFederatedUser(response);
            }
            user = provisionedFederateUser;
        }
        String tokenResponse = request.getParameter(TOKEN_RESPONSE);

        if (isAPIBasedAuthRequest(request)) {
            tokenResponse = base64URLDecode(request.getParameter(TOKEN_RESPONSE));
        }
        if (tokenResponse != null && !tokenResponse.contains(ERROR_CODE)) {
            String appID = FIDOUtil.getOrigin(request);
            if (isWebAuthnEnabled()) {
                if (user == null) {
                    user = processFido2UsernamelessAuthenticationResponse(tokenResponse);
                } else {
                    processFido2AuthenticationResponse(user, tokenResponse);
                }
            } else {
                processFidoAuthenticationResponse(user, appID, tokenResponse);
            }
            context.setSubject(user);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        FIDO_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
                diagnosticLogBuilder.resultMessage("Successfully processed FIDO authentication response.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context))
                        .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                LoggerUtils.getMaskedContent(user.getUserName()) : user.getUserName());
                Optional<String> optionalUserId = getUserId(user);
                optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                        userId));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FIDO authentication failed : " + tokenResponse);
            }
            throw new InvalidCredentialsException("FIDO device authentication failed ", user);
        }

    }

    private void setPasskeyDisplayName(String credentialId, String displayName, String username)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        if (StringUtils.isNotBlank(displayName)) {
            try {
                webAuthnService.updateFIDO2DeviceDisplayName(credentialId, displayName, username);
            } catch (FIDO2AuthenticatorClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Client error while updating the display name of passkey with credentialId: " +
                            credentialId, e);
                }
                throw new AuthenticationFailedException(
                        "Error while updating display name of passkey. Passkey enrollment is not available with " +
                                "credentialId : " + credentialId, e);
            } catch (FIDO2AuthenticatorServerException e) {
                throw new AuthenticationFailedException(
                        "A system error occurred while updating display name of passkey with credentialId : " +
                                credentialId, e);
            }
        }
    }

    @Override
    public boolean canHandle(javax.servlet.http.HttpServletRequest httpServletRequest) {

        String tokenResponse = httpServletRequest.getParameter(TOKEN_RESPONSE);
        String scenario = httpServletRequest.getParameter(SCENARIO);
        boolean canHandle = (null != tokenResponse || null != scenario);
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    FIDO_AUTH_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("FIDO authenticator handling the authentication.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;

    }

    @Override
    public String getContextIdentifier(
            javax.servlet.http.HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {

        return FIDOAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return FIDOAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    FIDO_AUTH_SERVICE, VALIDATE_FIDO_REQUEST);
            diagnosticLogBuilder.resultMessage("Validate fido authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        AuthenticatedUser user = getUsername(context);

        // If the username was initially obtained through the passkey identifier first page, the user needs to be
        // resolved by retrieving the collected username.
        if ((user == null) && isFidoAsFirstFactor(context) && isIDFInitiatedFromAuthenticator(context)) {
            String username = retrievePersistedUsername(context);
            user = resolveUserFromUsername(username, context);
        }

        //If the user is federated, retrieve the just-in-time provisioned federated user.
        if ((user != null) && user.isFederatedUser()) {
            AuthenticatedUser provisionedFederateUser = getProvisionedFederatedUser(user, context);
            if (provisionedFederateUser == null) {
                // If the provisionedFederateUser is blank, that means this is a login attempt by an unprovisioned
                // federated user.
                handleUnProvisionedFederatedUser(response);
            }
            user = provisionedFederateUser;
        }

        // Retrieving AppID
        // Origin as appID eg: https://example.com:8080
        String appID = resolveAppId(request);

        try {
            String redirectUrl = getRedirectUrl(response, user, appID, getLoginPage(), context);
            response.sendRedirect(redirectUrl);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        FIDO_AUTH_SERVICE, VALIDATE_FIDO_REQUEST);
                diagnosticLogBuilder.resultMessage("FIDO authentication request validation successful.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate FIDO authentication request", user, e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building FIDO page URL.", e);
        }
    }

    private boolean isIDFInitiatedFromAuthenticator(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(FIDOAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR));
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return false;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     * If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     * an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);

        List<String> requiredParameterList = new ArrayList<>();
        requiredParameterList.add(TOKEN_RESPONSE);
        authenticatorData.setRequiredParams(requiredParameterList);
        // Set Additional Data.
        AdditionalData additionalData = new AdditionalData();
        Map<String, String> additionalAuthenticationParam = new HashMap<>();
        String encodedChallengeData = base64URLEncode((String) context.getProperty(FIDOAuthenticatorConstants.
                AUTHENTICATOR_NAME + FIDOAuthenticatorConstants.CHALLENGE_DATA_SUFFIX));
        additionalAuthenticationParam.put(CHALLENGE_DATA, encodedChallengeData);
        additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParam);
        authenticatorData.setAdditionalData(additionalData);

        return Optional.of(authenticatorData);
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Get the i18n key defined to represent the authenticator name.
     *
     * @return the 118n key.
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_FIDO;
    }

    /**
     * Gets a FIDOAuthenticator instance.
     *
     * @return a FIDOAuthenticator.
     */
    public static FIDOAuthenticator getInstance() {

        return instance;
    }

    private void processFido2AuthenticationResponse(AuthenticatedUser user, String tokenResponse)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        webAuthnService.finishAuthentication(user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain(),
                tokenResponse);
    }

    private AuthenticatedUser processFido2UsernamelessAuthenticationResponse(String tokenResponse)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        return webAuthnService.finishUsernamelessAuthentication(tokenResponse);
    }

    private void processFidoAuthenticationResponse(AuthenticatedUser user, String appID, String tokenResponse)
            throws AuthenticationFailedException {

        U2FService u2FService = U2FService.getInstance();
        FIDOUser fidoUser = new FIDOUser(user.getUserName(), user.getTenantDomain(),
                user.getUserStoreDomain(), AuthenticateResponse.fromJson(tokenResponse));
        fidoUser.setAppID(appID);
        u2FService.finishAuthentication(fidoUser);
    }

    private AuthenticateRequestData initiateFidoAuthenticationRequest(AuthenticatedUser user, String appID)
            throws AuthenticationFailedException {

        U2FService u2FService = U2FService.getInstance();
        FIDOUser fidoUser = new FIDOUser(user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain(), appID);

        return u2FService.startAuthentication(fidoUser);
    }

    private String initiateFido2AuthenticationRequest(AuthenticatedUser user, String appID, AuthenticationContext
            context) throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();

        if (FrameworkUtils.isPreviousIdPAuthenticationFlowHandler(context)) {
            boolean isUserResolved = FrameworkUtils.getIsUserResolved(context);
            if (!isUserResolved && user != null) {
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(user.getUserName());
                String tenantDomain = MultitenantUtils.getTenantDomain(user.getUserName());
                ResolvedUserResult resolvedUserResult = FrameworkUtils.
                        processMultiAttributeLoginIdentification(tenantAwareUsername, tenantDomain);
                if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS
                        .equals(resolvedUserResult.getResolvedStatus())) {
                    tenantAwareUsername = resolvedUserResult.getUser().getUsername();
                    user.setUserName(resolvedUserResult.getUser().getUsername());
                    user.setUserId(resolvedUserResult.getUser().getUserID());
                    user.setUserStoreDomain(resolvedUserResult.getUser().getUserStoreDomain());
                }
            }
        }

        //Initiate the usernameless authentication process when either the user is unidentified or the identified user
        // lacks an enrolled passkey.
        if (user == null || !hasUserSetPasskeys(user.getUserName())) {
            return webAuthnService.startUsernamelessAuthentication(appID);
        }

        return webAuthnService.startAuthentication(user.getUserName(),
                user.getTenantDomain(), user.getUserStoreDomain(), appID);
    }

    private String initiateFido2PasskeyEnrollmentRequest(String appID, AuthenticatedUser user)
            throws AuthenticationFailedException {

        try {
            WebAuthnService webAuthnService = new WebAuthnService();
            Either<String, FIDO2RegistrationRequest> result =
                    webAuthnService.startFIDO2UsernamelessRegistration(appID, user.getUserName());

            if (result.isRight()) {
                return writeJson(result.right().get());
            } else {
                throw new AuthenticationFailedException("A system error occurred while serializing start " +
                        "passkey enrollment response for the appId :" + appID);
            }
        } catch (JsonProcessingException e) {
            throw new AuthenticationFailedException("A system error occurred while serializing start passkey " +
                    "enrollment response for the appId :" + appID);
        } catch (FIDO2AuthenticatorClientException e) {
            throw new AuthenticationFailedException("FIDO2 trusted origin: " + appID + " sent in the request is " +
                    "invalid.");
        }
    }

    private void processFido2PasskeyEnrollmentResponse(String challengeResponse, String username)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        try {
            webAuthnService.finishFIDO2Registration(challengeResponse, username);
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException("A system error occurred while finishing passkey enrollment.");
        } catch (FIDO2AuthenticatorClientException e) {
            throw new AuthenticationFailedException("Client error while finishing passkey enrollment.");
        }
    }

    private boolean hasUserSetPasskeys(String username) throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        return webAuthnService.isFidoKeyRegistered(username);
    }

    private String buildAbsoluteURL(String redirectUrl) throws URISyntaxException, URLBuilderException {

        URI uri = new URI(redirectUrl);
        if (uri.isAbsolute()) {
            return redirectUrl;
        } else {
            return ServiceURLBuilder.create().addPath(redirectUrl).build().getAbsolutePublicURL();
        }
    }

    private boolean isWebAuthnEnabled() {

        boolean webAuthnEnabled = false;
        String webAuthnStatus = IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED);
        if (StringUtils.isNotBlank(webAuthnStatus)) {
            webAuthnEnabled = Boolean.parseBoolean(webAuthnStatus);
        }

        return webAuthnEnabled;
    }

    private String getRedirectUrl(HttpServletResponse response, AuthenticatedUser user, String appID, String loginPage,
                                  AuthenticationContext context)
            throws AuthenticationFailedException, UnsupportedEncodingException, URLBuilderException,
            URISyntaxException {

        if (isWebAuthnEnabled()) {
            String data = initiateFido2AuthenticationRequest(user, appID, context);
            context.setProperty(FIDOAuthenticatorConstants.AUTHENTICATOR_NAME +
                    FIDOAuthenticatorConstants.CHALLENGE_DATA_SUFFIX, data);
            if (StringUtils.isNotBlank(data)) {
                String urlEncodedData = URLEncoder.encode(data, IdentityCoreConstants.UTF_8);
                return loginPage + ("?") + "&authenticators=" + getName() + ":" + "LOCAL" +
                        "&type=fido&sessionDataKey=" + context.getContextIdentifier() + "&data=" + urlEncodedData;
            }
        } else {
            AuthenticateRequestData data = initiateFidoAuthenticationRequest(user, appID);
            if (data != null) {
                String encodedData = URLEncoder.encode(data.toJson(), IdentityCoreConstants.UTF_8);
                return loginPage + ("?") + "&authenticators=" + getName() + ":" + "LOCAL" +
                        "&type=fido&sessionDataKey=" + context.getContextIdentifier() + "&data=" + encodedData;
            }
        }
        throw new AuthenticationFailedException("The failure occurred while initiating the authentication request " +
                "to create the public key credentials.");
    }

    private String resolveAppId(HttpServletRequest request) {

        String appID = FIDOUtil.getOrigin(request);
        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.APP_ID))) {
            appID = getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.APP_ID);
        }
        return appID;
    }

    private AuthenticatedUser getUsername(AuthenticationContext context) {

        //username from authentication context.
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                if (authenticatedUser.getUserStoreDomain() == null) {
                    authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
                }

                if (log.isDebugEnabled()) {
                    log.debug("username :" + authenticatedUser.toString());
                }
                break;
            }
        }

        return authenticatedUser;
    }

    private String getLoginPage() {

        String loginPage;
        if (isWebAuthnEnabled() && StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO2_AUTH))) {
            loginPage = getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_AUTH);
        } else if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO_AUTH))) {
            loginPage = getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO_AUTH);
        } else {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO_LOGIN);
        }
        return loginPage;
    }

    /** Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * Get the user id from the authenticated user.
     *
     * @param authenticatedUser AuthenticationContext.
     * @return User id.
     */
    private Optional<String> getUserId(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(authenticatedUser.getUserId());
        } catch (UserIdNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the user id from the authenticated user.", e);
            }
        }
        return Optional.empty();
    }

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                authenticatedUser = new AuthenticatedUser(stepConfig.getAuthenticatedUser());
                break;
            }
        }
        if (context.getLastAuthenticatedUser() != null && context.getLastAuthenticatedUser().getUserName() != null) {
            authenticatedUser = context.getLastAuthenticatedUser();
        }
        return authenticatedUser;
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param username The username of the user.
     * @param context  The authentication context.
     */
    private AuthenticatedUser resolveUserFromUsername(String username, AuthenticationContext context) {

        username = FrameworkUtils.preprocessUsername(username, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method is used to check whether FIDO is configured as the first factor.
     *
     * @param context The authentication context.
     */
    private boolean isFidoAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || FrameworkUtils.isPreviousIdPAuthenticationFlowHandler(context));
    }

    /**
     * This method is used to persist the username in the context.
     *
     * @param context  The authentication context.
     * @param username The username provided by the user.
     */
    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

    /**
     * This method is used to retrieve the persisted username in the context.
     *
     * @param context The authentication context.
     */
    public String retrievePersistedUsername(AuthenticationContext context) {

        Map<String, Map<String, Object>> contextRuntimeParams =
                (Map<String, Map<String, Object>>) context.getProperty("RUNTIME_PARAMS");
        if (contextRuntimeParams != null) {
            Map<String, Object> identifierParams =
                    contextRuntimeParams.get(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS);
            if (identifierParams != null) {
                return (String) identifierParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
        }
        }
        return null; // Return null if not found.
    }

    private boolean isUsernamelessAuthenticationEnabled(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    FIDOUtil.getFIDOAuthenticatorConfig(ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION,
                            tenantDomain));
        } catch (FIDOAuthenticatorServerException exception) {
            throw new AuthenticationFailedException("Error occurred while getting the authenticator configuration");
        }
    }

    private boolean isPasskeyProgressiveEnrollmentEnabled(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    FIDOUtil.getFIDOAuthenticatorConfig(ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT,
                            tenantDomain));
        } catch (FIDOAuthenticatorServerException exception) {
            throw new AuthenticationFailedException("Error occurred while getting the authenticator configuration");
        }
    }

    /**
     * This method is used to mask the username.
     *
     * @param username The username to be masked.
     */
    private String getMaskedUsername(String username) {

        if (LoggerUtils.isLogMaskingEnable) {
            return LoggerUtils.getMaskedContent(username);
        }
        return username;
    }

    private void addPasskeyEnrollmentConfigToEndpointParams(AuthenticationContext context,
                                                            boolean enablePasskeyProgressiveEnrollment) {

        if (!context.getEndpointParams().containsKey(ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT)) {
            context.addEndpointParam(ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT,
                    enablePasskeyProgressiveEnrollment);
        }
    }

    private String base64URLDecode(String value) {

        return new String(
                Base64.getUrlDecoder().decode(value),
                StandardCharsets.UTF_8);
    }

    private String base64URLEncode(String value) {

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private boolean isAPIBasedAuthRequest(HttpServletRequest request) {

        return Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.IS_API_BASED_AUTH_FLOW));
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }
        // If the user is federated, we need to check whether the user is already jit provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw new AuthenticationFailedException("No federated user found");
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Get the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param context                    AuthenticationContext
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser getProvisionedFederatedUser(AuthenticatedUser authenticatedUserInContext,
                                                          AuthenticationContext context)
            throws AuthenticationFailedException {

        // We need to identify the username that the server is using to identify the user. This is needed to handle
        // federated scenarios, since for federated users, the username in the authentication context is not same as
        // the username when the user is provisioned to the server.
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserInContext, context);

        // If the mappedLocalUsername is blank, that means this is an initial login attempt by an unprovisioned
        // federated user.
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        if (authenticatedUserInContext.isFederatedUser() && !isInitialFederationAttempt) {
            // At this point, the authenticating user is in our system but has a different mapped username compared
            // to the identifier that is in the authentication context. Therefore, we need to have a new
            // AuthenticatedUser object with the mapped local username to identify the user.
            AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
            authenticatingUser.setUserName(mappedLocalUsername);
            authenticatingUser.setUserStoreDomain(getFederatedUserstoreDomain(authenticatedUserInContext,
                    context.getTenantDomain()));
            return authenticatingUser;
        }
        return null;
    }

    /**
     * Get the JIT provisioning userstore domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning userstore domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserstoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserstore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting userstore: %s as the provisioning userstore for user: %s in tenant: %s",
                    provisionedUserstore, user.getUserName(), tenantDomain));
        }
        return provisionedUserstore;
    }

    private void handleUnProvisionedFederatedUser(HttpServletResponse response) throws AuthenticationFailedException {

        try {
            response.sendRedirect(getProvisionedUserNotFoundRedirectUrl(response));
        } catch (URLBuilderException | URISyntaxException | UnsupportedEncodingException e) {
            throw new AuthenticationFailedException("Error while building provisioned user not found redirect URL.", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate provisioned user not found redirect request",
                    e);
        }
    }

    private String getProvisionedUserNotFoundRedirectUrl(HttpServletResponse response)
            throws UnsupportedEncodingException, URLBuilderException, URISyntaxException {

        String redirectURL = ConfigurationFacade.getInstance().getAuthenticationEndpointErrorURL();

        redirectURL = response.encodeRedirectURL(redirectURL + ("?")) +
                "&statusMsg=" + URLEncoder.encode(
                FIDOAuthenticatorConstants.AUTHENTICATION_FAILED_PROVISIONED_USER_NOT_FOUND_ERROR_MESSAGE,
                IdentityCoreConstants.UTF_8) + "&status=" + URLEncoder.encode(FIDOAuthenticatorConstants
                .AUTHENTICATION_FAILED_STATUS, IdentityCoreConstants.UTF_8);

        return buildAbsoluteURL(redirectURL);
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp =
                    FIDOAuthenticatorServiceDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format("No IDP found with the name IDP: %s in tenant: %s", idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(
                    String.format("Error occurred while getting IDP: %s from tenant: %s", idpName, tenantDomain));
        }
    }
}
