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
import org.wso2.carbon.identity.application.authenticator.fido.dto.FIDOUser;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

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

        AuthenticatedUser user;
        String tokenResponse = request.getParameter("tokenResponse");
        if (tokenResponse != null && !tokenResponse.contains("errorCode")) {
            String appID = FIDOUtil.getOrigin(request);
            user = getUsername(context);

            if (isWebAuthnEnabled()) {
                processFido2AuthenticationResponse(user, tokenResponse);
            } else {
                processFidoAuthenticationResponse(user, appID, tokenResponse);
            }
            context.setSubject(user);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FIDO authentication failed : " + tokenResponse);
            }
            user = getUsername(context);
            throw new InvalidCredentialsException("FIDO device authentication failed ", user);
        }

    }

    @Override
    public boolean canHandle(javax.servlet.http.HttpServletRequest httpServletRequest) {

        String tokenResponse = httpServletRequest.getParameter("tokenResponse");
        return null != tokenResponse;

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

        AuthenticatedUser user = getUsername(context);
        // Retrieving AppID
        // Origin as appID eg: https://example.com:8080
        String appID = resolveAppId(request);

        try {
            String redirectUrl = getRedirectUrl(request, response, user, appID, getLoginPage());
            response.sendRedirect(redirectUrl);

        } catch (IOException e) {
            throw new AuthenticationFailedException("Could not initiate FIDO authentication request", user, e);
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

    private String initiateFido2AuthenticationRequest(AuthenticatedUser user, String appID)
            throws AuthenticationFailedException {

        WebAuthnService webAuthnService = new WebAuthnService();

        return webAuthnService.startAuthentication(user.getUserName(),
                user.getTenantDomain(), user.getUserStoreDomain(), appID);
    }

    private String getRedirectUrl(boolean isDataNull, String loginPage, String urlEncodedData, HttpServletRequest request,
                                  HttpServletResponse response, AuthenticatedUser user)
            throws UnsupportedEncodingException {

        String redirectURL;
        if (!isDataNull) {
            redirectURL = loginPage + ("?")
                    + "&authenticators=" + getName() + ":" + "LOCAL" + "&type=fido&sessionDataKey=" +
                    request.getParameter("sessionDataKey") +
                    "&data=" + urlEncodedData;
        } else {
            redirectURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
            redirectURL = response.encodeRedirectURL(redirectURL + ("?")) + "&failedUsername=" +
                    URLEncoder.encode(user.getUserName(), IdentityCoreConstants.UTF_8) +
                    "&statusMsg=" + URLEncoder.encode(FIDOAuthenticatorConstants.AUTHENTICATION_ERROR_MESSAGE,
                    IdentityCoreConstants.UTF_8) + "&status=" + URLEncoder.encode(FIDOAuthenticatorConstants
                    .AUTHENTICATION_STATUS, IdentityCoreConstants.UTF_8);
        }

        return redirectURL;
    }

    private boolean isWebAuthnEnabled() {

        boolean webAuthnEnabled = false;
        String webAuthnStatus = IdentityUtil.getProperty(FIDOAuthenticatorConstants.WEBAUTHN_ENABLED);
        if (StringUtils.isNotBlank(webAuthnStatus)) {
            webAuthnEnabled = Boolean.parseBoolean(webAuthnStatus);
        }

        return webAuthnEnabled;
    }

    private String getRedirectUrl(HttpServletRequest request, HttpServletResponse response, AuthenticatedUser user,
                                  String appID, String loginPage) throws AuthenticationFailedException,
            UnsupportedEncodingException {

        String redirectUrl;
        if (isWebAuthnEnabled()) {
            String data = initiateFido2AuthenticationRequest(user, appID);
            boolean isDataNull = StringUtils.isBlank(data);
            redirectUrl = getRedirectUrl(isDataNull, loginPage, URLEncoder.encode(data,
                    IdentityCoreConstants.UTF_8), request, response, user);
        } else {
            AuthenticateRequestData data = initiateFidoAuthenticationRequest(user, appID);
            boolean isDataNull = (data == null);
            String encodedData = null;
            if (!isDataNull) {
                encodedData = URLEncoder.encode(data.toJson(), IdentityCoreConstants.UTF_8);
            }
            redirectUrl = getRedirectUrl(isDataNull, loginPage, encodedData, request, response, user);
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

    private AuthenticatedUser getUsername(AuthenticationContext context) throws AuthenticationFailedException {

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
        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Could not locate an authenticated username from previous steps " +
                    "of the sequence. Hence cannot continue with FIDO authentication.");
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

}
