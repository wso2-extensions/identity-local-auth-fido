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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.*;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.ActionIDs.VALIDATE_FIDO_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants.LogConstants.FIDO_AUTH_SERVICE;

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

        // Check if progressive registration is enabled. If not trigger the authentication flow excluding the fido key
        // progressive registration.
        if (!isProgressiveRegEnabled()) {
            return super.process(request, response, context);
        }

        // If the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // If an authentication complete request comes go through this flow.
        if (StringUtils.isNotEmpty(request.getParameter(TOKEN_RESPONSE)) &&
                !(!StringUtils.isEmpty(request.getParameter(SCENARIO)) &&
                        request.getParameter(SCENARIO).equals(ScenarioTypes.INIT_FIDO_ENROL))) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // If a fido key registration request comes set a property to the context mentioning the user consent
        // is received.
        if (!StringUtils.isEmpty(request.getParameter(SCENARIO)) &&
                (request.getParameter(SCENARIO).equals(ScenarioTypes.INIT_FIDO_ENROL) ||
                        request.getParameter(SCENARIO).equals(ScenarioTypes.IDF_INIT_FIDO_ENROL))) {
            context.setProperty(IS_USER_CONSENT_FOR_REG_RECEIVED, true);
        }

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);

        if (authenticatedUser != null) {
            boolean isFidoKeyRegistered = isFidoKeyRegistered(authenticatedUser.getUserName());
            if (isFidoKeyRegistered) {
                // If the user have a registered fido key and if the user initiated a registration request,
                // then inform the user that a key is already exists and disregard the registration flow.
                if (isUserRegistrationConsentReceived(context)) {
                    redirectUserToFIDOKeyExistPage(response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
                // If the user has a registered fido key, then initiate the authentication flow.
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // If the user does not have a registered fido key and if the registration consent is not received,
                // then redirect the user to the consent page prior to initiating the registration request.
                if (isUserRegistrationConsentReceived(context)) {
                    redirectUserToRegistrationConsentPage(response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
                if (!FrameworkUtils.isPreviousIdPAuthenticationFlowHandler(context)) {
                    return handleFidoRegistrationScenario(request, response, context);
                } else {
                    persistUsername(context, authenticatedUser.getUserName());
                    context.setProperty(IS_USER_CONSENT_FOR_REG_RECEIVED, true);
                    return AuthenticatorFlowStatus.FAIL_COMPLETED;
                }
            }
        } else {

            if (isUserRegistrationConsentReceived(context)) {
                if (!StringUtils.isEmpty(request.getParameter(USER_NAME))) {
                    persistUsername(context, request.getParameter(USER_NAME));
                }
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }

            if (isFidoAsFirstFactor(context)) {
                if (StringUtils.isEmpty(request.getParameter(USER_NAME))) {
                    redirectUserToFIDOIdentifierFirstPage(response, context);
                    context.setProperty(FIDOAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
                // If an authentication request initiated from the custom FIDO identifier page, go through this flow.
                if (!StringUtils.isEmpty(request.getParameter(SCENARIO)) &&
                        request.getParameter(SCENARIO).equals(ScenarioTypes.IDF_INIT_FIDO_AUTH)) {
                    persistUsername(context, request.getParameter(USER_NAME));
                    authenticatedUser = resolveUserFromRequest(request, context);
                    authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                    setResolvedUserInContext(context, authenticatedUser);
                    initiateAuthenticationRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            }
            log.debug("The user does not exist in the user stores.");
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    private static boolean isUserRegistrationConsentReceived(AuthenticationContext context) {

        return context.getProperty(IS_USER_CONSENT_FOR_REG_RECEIVED) != null &&
                context.getProperty(IS_USER_CONSENT_FOR_REG_RECEIVED).equals(true);
    }

    private AuthenticatorFlowStatus handleFidoRegistrationScenario(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        if (request.getParameter(SCENARIO) != null && !request.getParameter(SCENARIO).isEmpty()) {
            String scenario = request.getParameter(SCENARIO);
            switch (scenario) {
                case ScenarioTypes.INIT_FIDO_ENROL:
                    // Redirect the user in this flow upon user initiating the fido key
                    // registration request
                    initiateRegistrationRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                case ScenarioTypes.FINISH_FIDO_ENROL:
                    // Redirect the user in this flow upon user requesting to finish the fido
                    // key registration
                    processRegistrationResponse(request, response, context);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                case ScenarioTypes.CANCEL_FIDO_ENROL:
                    // Redirect the user in this flow upon user cancelling the fido key
                    // registration
                    processRegistrationResponse(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }
        initiateRegistrationRequest(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    private void redirectUserToFIDOIdentifierFirstPage(HttpServletResponse response, AuthenticationContext context)
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

    private void redirectUserToRegistrationConsentPage(HttpServletResponse response, AuthenticationContext context) 
            throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Registration failed!. Cannot proceed further without " +
                    "identifying the user");
        }

        try {
            String registrationConsentPageURL = getFidoKeyStatusPageURL(context, false);
            response.sendRedirect(registrationConsentPageURL);
            context.setProperty("isUserConsentForRegReceived", true);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate FIDO registration consent request", user, e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building FIDO registration consent page URL.", e);
        }
    }

    private void redirectUserToFIDOKeyExistPage(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Registration failed!. Cannot redirect the suer to the FIDO key " +
                    "exist page without identifying the user.");
        }
        try {
            String fidoKeyExistPageURL = getFidoKeyStatusPageURL(context, true);
            response.sendRedirect(fidoKeyExistPageURL);
            context.setProperty("isUserConsentForRegReceived", false);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not redirect the user to FIDO key exist page", e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building FIDO key existing display page URL.", e);
        }
    }

    private void initiateRegistrationRequest(HttpServletRequest request, HttpServletResponse response,
                AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Registration failed!. Cannot proceed further without " +
                    "identifying the user");
        }

        // Retrieving AppID
        // Origin as appID eg: https://example.com:8080
        String appID = resolveAppId(request);

        try {
            String registrationPageURL = getRegistrationPageURL(appID, user, context);
            response.sendRedirect(registrationPageURL);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate FIDO registration request", user, e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building FIDO registration page URL.", e);
        }
    }

    private String getRegistrationPageURL(String appID, AuthenticatedUser user, AuthenticationContext context)
            throws AuthenticationFailedException, UnsupportedEncodingException, URLBuilderException,
            URISyntaxException {

        String registrationPageURL;

        String data = initiateFido2RegistrationRequest(appID, user);
        boolean isDataNull = StringUtils.isBlank(data);
        String urlEncodedData = null;
        if (!isDataNull) {
            urlEncodedData = URLEncoder.encode(data, IdentityCoreConstants.UTF_8);
        }

        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO2_REG))) {
            registrationPageURL =
                    getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_REG);
        } else {
            registrationPageURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_REG);
        }

        registrationPageURL = registrationPageURL + ("?") + "&authenticators=" + getName() + ":" + "LOCAL" +
                "&type=fido&sessionDataKey=" + context.getContextIdentifier() + "&data=" + urlEncodedData;

        return buildAbsoluteURL(registrationPageURL);
    }

    private String getFidoKeyStatusPageURL(AuthenticationContext context, boolean isKeyExist)
            throws URLBuilderException, URISyntaxException {

        String fidoKeyStatusPageURL;

        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(FIDOAuthenticatorConstants.FIDO2_KEY_STATUS))) {
            fidoKeyStatusPageURL =
                    getAuthenticatorConfig().getParameterMap().get(FIDOAuthenticatorConstants.FIDO2_KEY_STATUS);
        } else {
            fidoKeyStatusPageURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_KEY_STATUS);
        }

        fidoKeyStatusPageURL = fidoKeyStatusPageURL + ("?") + "&authenticators=" + getName() + ":" +
                "LOCAL" + "&type=fido&sessionDataKey=" + context.getContextIdentifier() + "&keyExist=" + isKeyExist;

        return buildAbsoluteURL(fidoKeyStatusPageURL);
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
                    FIDOAuthenticatorConstants.URI_LOGIN, FIDOAuthenticatorConstants.URI_FIDO2_IDENTIFIER_AUTH);
        }

        fidoIdentifierAuthPageURL = fidoIdentifierAuthPageURL + ("?") + "&authenticators=" + getName() + ":" +
                "LOCAL" + "&type=fido&sessionDataKey=" + context.getContextIdentifier();

        return buildAbsoluteURL(fidoIdentifierAuthPageURL);
    }

    protected void processRegistrationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getUsername(context);
        if (user == null) {
            throw new AuthenticationFailedException("Registration failed!. Cannot proceed further without " +
                    "identifying the user");
        }

        String challengeResponse = request.getParameter(CHALLENGE_RESPONSE);
        String displayName = request.getParameter(FIDO_KEY_DISPLAY_NAME);

        if (challengeResponse != null && !challengeResponse.contains(ERROR_CODE)) {

            processFido2RegistrationResponse(challengeResponse, user.getUserName());

            // Parse the JSON string into a JSONObject
            JSONObject json = new JSONObject(challengeResponse);

            // Extract the "credential" object
            JSONObject credentialObject = json.getJSONObject(FIDO_KEY_CREDENTIAL);

            // Extract the "id" from the "credential" object
            String credentialId = credentialObject.getString(FIDO_KEY_ID);

            // Set the key name
            setFIDO2DeviceDisplayName(credentialId, displayName, user.getUserName());

            context.setSubject(user);
            context.setProperty(IS_USER_CONSENT_FOR_REG_RECEIVED, false);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FIDO registration failed : " + challengeResponse);
            }
            throw new InvalidCredentialsException("FIDO device registration failed ", user);
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
        String tokenResponse = request.getParameter(TOKEN_RESPONSE);
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

    private void setFIDO2DeviceDisplayName(String credentialId, String displayName, String username)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        if (StringUtils.isNotBlank(displayName)) {
            try {
                webAuthnService.updateFIDO2DeviceDisplayName(credentialId, displayName, username);
            } catch (FIDO2AuthenticatorClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Client error while updating the display name of FIDO device with credentialId: " +
                            credentialId, e);
                }

                throw new AuthenticationFailedException("Error while updating display name of device. FIDO2 device " +
                        "registration is not available with credentialId : " + credentialId, e);

            } catch (FIDO2AuthenticatorServerException e) {
                throw new AuthenticationFailedException("A system error occurred while updating display name of " +
                        "device with credentialId : " + credentialId, e);
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

    @Override
    protected boolean retryAuthenticationEnabled() {

        return false;
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

        if (user == null) {
            return webAuthnService.startUsernamelessAuthentication(appID);
        }

        return webAuthnService.startAuthentication(user.getUserName(),
                user.getTenantDomain(), user.getUserStoreDomain(), appID);
    }

    private String initiateFido2RegistrationRequest(String appID, AuthenticatedUser user)
            throws AuthenticationFailedException {

        try {
            WebAuthnService webAuthnService = new WebAuthnService();
            Either<String, FIDO2RegistrationRequest> result =
                    webAuthnService.startFIDO2UsernamelessRegistration(appID, user.getUserName());

            if (result.isRight()) {
                return org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil.writeJson(
                        result.right().get());
            } else {
                throw new AuthenticationFailedException("A system error occurred while serializing start " +
                        "registration response for the appId :" + appID);
            }
        } catch (JsonProcessingException e) {
            throw new AuthenticationFailedException("A system error occurred while serializing start registration " +
                    "response for the appId :" + appID);
        } catch (FIDO2AuthenticatorClientException e) {
            throw new AuthenticationFailedException("FIDO2 trusted origin: " + appID + " sent in the request is " +
                    "invalid.");
        }
    }

    private void processFido2RegistrationResponse (String challengeResponse, String username)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        try {
            webAuthnService.finishFIDO2Registration(challengeResponse, username);
        } catch (FIDO2AuthenticatorServerException e) {
            throw new AuthenticationFailedException("A system error occurred while finishing device registration.");
        } catch (FIDO2AuthenticatorClientException e) {
            throw new AuthenticationFailedException("Client error while FIDO2 device finish registration.");
        }
    }

    private boolean isFidoKeyRegistered (String username) throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();
        return webAuthnService.isFidoKeyRegistered(username);
    }

    private String getRedirectUrl(boolean isDataNull, String loginPage, String urlEncodedData,
            HttpServletResponse response, AuthenticatedUser user, AuthenticationContext context)
            throws UnsupportedEncodingException, URLBuilderException, URISyntaxException {

        String redirectURL;
        if (!isDataNull) {
            redirectURL = loginPage + ("?")
                    + "&authenticators=" + getName() + ":" + "LOCAL" + "&type=fido&sessionDataKey=" +
                    context.getContextIdentifier() + "&data=" + urlEncodedData;
        } else {
            redirectURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
            redirectURL = response.encodeRedirectURL(redirectURL + ("?")) + "&failedUsername=" +
                    URLEncoder.encode(user.getUserName(), IdentityCoreConstants.UTF_8) +
                    "&statusMsg=" + URLEncoder.encode(FIDOAuthenticatorConstants.AUTHENTICATION_ERROR_MESSAGE,
                    IdentityCoreConstants.UTF_8) + "&status=" + URLEncoder.encode(FIDOAuthenticatorConstants
                    .AUTHENTICATION_STATUS, IdentityCoreConstants.UTF_8);
        }

        return buildAbsoluteURL(redirectURL);
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

    private boolean isProgressiveRegEnabled() {

        boolean progressiveRegEnabled = false;
        String progressiveRegStatus = IdentityUtil.getProperty(PROGRESSIVE_REG_ENABLED);
        if (StringUtils.isNotBlank(progressiveRegStatus)) {
            progressiveRegEnabled = Boolean.parseBoolean(progressiveRegStatus);
        }

        return progressiveRegEnabled;
    }

    private String getRedirectUrl(HttpServletResponse response, AuthenticatedUser user, String appID, String loginPage,
                                  AuthenticationContext context)
            throws AuthenticationFailedException, UnsupportedEncodingException, URLBuilderException,
            URISyntaxException {

        String redirectUrl;
        if (isWebAuthnEnabled()) {
            if (user != null && !isFidoKeyRegistered(user.getUserName())) {
                user = null;
            }
            String data = initiateFido2AuthenticationRequest(user, appID, context);
            boolean isDataNull = StringUtils.isBlank(data);
            String urlEncodedData = null;
            if (!isDataNull) {
                urlEncodedData = URLEncoder.encode(data, IdentityCoreConstants.UTF_8);
            }
            redirectUrl = getRedirectUrl(isDataNull, loginPage, urlEncodedData, response, user, context);
        } else {
            AuthenticateRequestData data = initiateFidoAuthenticationRequest(user, appID);
            boolean isDataNull = (data == null);
            String encodedData = null;
            if (!isDataNull) {
                encodedData = URLEncoder.encode(data.toJson(), IdentityCoreConstants.UTF_8);
            }
            redirectUrl = getRedirectUrl(isDataNull, loginPage, encodedData, response, user, context);
        }
        return redirectUrl;
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
     * This method is used to resolve the username from authentication request.
     *
     * @param request The httpServletRequest.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private String resolveUsernameFromRequest(HttpServletRequest request) throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new AuthenticationFailedException("Username cannot be null or empty");
        }
        return identifierFromRequest;
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = resolveUsernameFromRequest(request);
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
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser The authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {
        User user = getUser(authenticatedUser);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           The authentication context.
     * @param authenticatedUser The authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            String username = authenticatedUser.getUserName();
            authenticatedUser.setAuthenticatedSubjectIdentifier(username);
            context.setSubject(authenticatedUser);

            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            currentStepConfig.setAuthenticatedUser(authenticatedUser);
            currentStepConfig.setAuthenticatedIdP(FIDOAuthenticatorConstants.LOCAL_AUTHENTICATOR);
        }
    }

    /**
     * This method is used to check whether FIDO is configured as the first factor.
     *
     * @param context           The authentication context.
     */
    private boolean isFidoAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || FrameworkUtils.isPreviousIdPAuthenticationFlowHandler(context));
    }

    /**
     * This method is used to persist the username in the context.
     *
     * @param context           The authentication context.
     * @param username          The username provided by the user.
     * */
    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

}
