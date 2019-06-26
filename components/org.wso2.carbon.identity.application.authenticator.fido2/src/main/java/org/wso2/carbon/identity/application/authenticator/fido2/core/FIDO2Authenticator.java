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
import org.wso2.carbon.identity.application.authenticator.fido2.dto.AssertionRequestWrapper;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.SuccessfulAuthenticationResult;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.List;

/**
 * FIDO WebAuthn Specification based authenticator.
 */
public class FIDO2Authenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static Log log = LogFactory.getLog(FIDO2Authenticator.class);
    private static FIDO2Authenticator instance = new FIDO2Authenticator();

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

            WebAuthnService webAuthnService = WebAuthnService.getInstance();
            Either<List<String>, SuccessfulAuthenticationResult> assertionResult;
            try {
                assertionResult = webAuthnService
                        .finishAuthentication(user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain(),
                        appID, tokenResponse);
            } catch (FIDO2AuthenticatorException | IOException e) {
                throw new InvalidCredentialsException("FIDO device authentication failed for user : ", user);
            }

            if(assertionResult.isLeft()) {
                throw new InvalidCredentialsException("FIDO device authentication failed for user : ", user);
            }
            context.setSubject(user);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FIDO authentication failed : " + tokenResponse);
            }
            user = getUsername(context);
            throw new InvalidCredentialsException("FIDO device authentication failed for user : ", user);
        }

    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        String tokenResponse = httpServletRequest.getParameter("tokenResponse");
        return null != tokenResponse;

    }

    @Override
    public String getContextIdentifier(
            HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return FIDO2AuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return FIDO2AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        //FIDO BE service component
        WebAuthnService webAuthnService = WebAuthnService.getInstance();
        AuthenticatedUser user = null;
        try {
            // Authentication page's URL.
            String loginPage;
            if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                    .get(FIDO2AuthenticatorConstants.FIDO_AUTH))) {
                loginPage = getAuthenticatorConfig().getParameterMap().get(FIDO2AuthenticatorConstants.FIDO_AUTH);
            } else {
                loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(FIDO2AuthenticatorConstants.URI_LOGIN, FIDO2AuthenticatorConstants.URI_FIDO_LOGIN);
            }

            // Username from basic authenticator.
            user = getUsername(context);

            // Retrieving AppID
            // Origin as appID eg: https://example.com:8080
            String appID = FIDOUtil.getOrigin(request);
            if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                    .get(FIDO2AuthenticatorConstants.APP_ID))) {
                appID = getAuthenticatorConfig().getParameterMap().get(FIDO2AuthenticatorConstants.APP_ID);
            }

            //calls BE service method to generate challenge.
            Either<List<String>, AssertionRequestWrapper> requestWrapper = webAuthnService.startAuthentication(user.getUserName(),
                    user.getTenantDomain(), user.getUserStoreDomain(), appID);

            //redirect to FIDO login page
            if (requestWrapper.isRight()) {
                String redirectURL = loginPage + ("?")
                        + "&authenticators=" + getName() + ":" + "LOCAL" + "&type=fido&sessionDataKey=" +
                        request.getParameter("sessionDataKey") +
                        "&data=" + URLEncoder.encode(FIDOUtil.writeJson(requestWrapper.right().get()), IdentityCoreConstants.UTF_8);
                response.sendRedirect(redirectURL);
            } else {
                String redirectURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                redirectURL = response.encodeRedirectURL(redirectURL + ("?")) + "&failedUsername=" + URLEncoder.encode(user.getUserName(), IdentityCoreConstants.UTF_8) +
                        "&statusMsg=" + URLEncoder.encode(FIDO2AuthenticatorConstants.AUTHENTICATION_ERROR_MESSAGE, IdentityCoreConstants.UTF_8) +
                        "&status=" + URLEncoder.encode(FIDO2AuthenticatorConstants.AUTHENTICATION_STATUS, IdentityCoreConstants.UTF_8);
                response.sendRedirect(redirectURL);
            }

        } catch (FIDO2AuthenticatorException | IOException e) {
            throw new AuthenticationFailedException(
                    "Could not initiate FIDO authentication request", user, e);
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return false;
    }

    private AuthenticatedUser getUsername(AuthenticationContext context) throws AuthenticationFailedException {
        //username from authentication context.
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
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
        if(authenticatedUser == null){
            throw new AuthenticationFailedException("Could not locate an authenticated username from previous steps " +
                    "of the sequence. Hence cannot continue with FIDO authentication.");
        }
        return authenticatedUser;
    }


    /**
     * Gets a FIDO2Authenticator instance.
     *
     * @return a FIDO2Authenticator.
     */
    public static FIDO2Authenticator getInstance() {
        return instance;
    }

}