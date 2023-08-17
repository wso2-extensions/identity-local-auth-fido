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

import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
        return super.process(request, response, context);
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
        String tokenResponse = request.getParameter("tokenResponse");
        if (tokenResponse != null && !tokenResponse.contains("errorCode")) {
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

    @Override
    public boolean canHandle(javax.servlet.http.HttpServletRequest httpServletRequest) {

        String tokenResponse = httpServletRequest.getParameter("tokenResponse");
        boolean canHandle = null != tokenResponse;
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

        if (user == null) {return webAuthnService.startUsernamelessAuthentication(appID);
        }

        return webAuthnService.startAuthentication(user.getUserName(),
                user.getTenantDomain(), user.getUserStoreDomain(), appID);
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

    private String getRedirectUrl(HttpServletResponse response, AuthenticatedUser user, String appID, String loginPage,
            AuthenticationContext context)
            throws AuthenticationFailedException, UnsupportedEncodingException, URLBuilderException,
            URISyntaxException {

        String redirectUrl;
        if (isWebAuthnEnabled()) {
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
}
