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

package org.wso2.carbon.identity.application.authenticator.fido2;

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
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.MessageFormat;

/**
 * FIDO UAF Specification based authenticator.
 */
public class FIDO2Authenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(FIDO2Authenticator.class);

    private static FIDO2Authenticator instance = new FIDO2Authenticator();
    private static final String AUTHENTICATOR_NAME = "FIDO2Authenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "fido-uaf";
    private static final String AUTHENTICATION_STATUS = "Authentication Failed !";
    private static final String AUTHENTICATION_ERROR_MESSAGE = "No registered device found, Please register your " +
            "device before sign in.";

    private static final String FIDO2_AUTH = "Fido2Auth";
    private static final String APP_ID = "AppID";

    private static final String URI_LOGIN = "login.do";
    private static final String URI_FIDO_LOGIN = "fido2-auth.jsp";

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

            WebAuthnService webAuthnService = new WebAuthnService();
            webAuthnService.finishAuthentication(user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain(),
                    tokenResponse);
            context.setSubject(user);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FIDO UAF authentication failed : " + tokenResponse);
            }
            user = getUsername(context);
            throw new InvalidCredentialsException("FIDO device authentication failed ", user);
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

        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = new AuthenticatedUser();
        String username = request.getParameter("username");
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        UserStoreManager userStoreManager;
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = FIDO2AuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = ((UserStoreManager) userRealm.getUserStoreManager());
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " + tenantId);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if(log.isDebugEnabled()){
                log.debug("FIDO UAF authentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }


        String appID = resolveAppId(request);
        user.setTenantDomain(tenantDomain);
        user.setUserName(MultitenantUtils.getTenantAwareUsername(username));
        user.setUserStoreDomain("PRIMARY");
        try {
            String redirectUrl = getRedirectUrl(request, response, user, appID, getLoginPage());
            response.sendRedirect(redirectUrl);

        } catch (IOException e) {
            throw new AuthenticationFailedException(MessageFormat.format("Could not initiate FIDO UAF " +
                    "authentication request for user : {0}", user), e);
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
    public static FIDO2Authenticator getInstance() {

        return instance;
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
                    "&statusMsg=" + URLEncoder.encode(AUTHENTICATION_ERROR_MESSAGE, IdentityCoreConstants.UTF_8)
                    + "&status=" + URLEncoder.encode(AUTHENTICATION_STATUS, IdentityCoreConstants.UTF_8);
        }

        return redirectURL;
    }

    private String getRedirectUrl(HttpServletRequest request, HttpServletResponse response, AuthenticatedUser user,
                                  String appID, String loginPage) throws AuthenticationFailedException,
            UnsupportedEncodingException {

        String redirectUrl;
            WebAuthnService webAuthnService = new WebAuthnService();

            String data = webAuthnService.startAuthentication(user.getUserName(),
                    user.getTenantDomain(), user.getUserStoreDomain(), appID);
            boolean isDataNull = StringUtils.isBlank(data);
            redirectUrl = getRedirectUrl(isDataNull, loginPage, URLEncoder.encode(data,
                    IdentityCoreConstants.UTF_8), request, response, user);

        return redirectUrl;
    }

    private String resolveAppId(HttpServletRequest request) {

        String appID = FIDOUtil.getOrigin(request);
        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap()
                .get(APP_ID))) {
            appID = getAuthenticatorConfig().getParameterMap().get(APP_ID);
        }
        return appID;
    }

    private AuthenticatedUser getUsername(AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                if (authenticatedUser.getUserStoreDomain() == null) {
                    authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
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
        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap().get(FIDO2_AUTH))) {
            loginPage = getAuthenticatorConfig().getParameterMap().get(FIDO2_AUTH);
        } else {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(URI_LOGIN, URI_FIDO_LOGIN);
        }
        return loginPage;
    }

}
