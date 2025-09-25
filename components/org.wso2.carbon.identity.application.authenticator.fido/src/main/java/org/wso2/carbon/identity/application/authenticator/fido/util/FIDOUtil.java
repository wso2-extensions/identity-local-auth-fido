/*
 * Copyright (c) 2015-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.application.authenticator.fido.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * FIDOUtil class for FIDO authentication component.
 */
public class FIDOUtil {

    private static final Log log = LogFactory.getLog(FIDOUtil.class);

    private FIDOUtil() {
    }

	public static String getOrigin(HttpServletRequest request) {

		return request.getScheme() + "://" + request.getServerName() + ":" +
		       request.getServerPort();
	}

    public static String getUniqueUsername(HttpServletRequest request, String username) {
        return request.getServerName() + "/" + username;
    }

    public static String getDomainName(String username) {
        int index = username.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        if (index < 0) {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }
        return username.substring(0, index);
    }

    public static String getUsernameWithoutDomain(String username) {
        int index = username.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        if (index < 0) {
            return username;
        }
        return username.substring(index + 1, username.length());
    }

    /**
     * Get fido authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws FIDOAuthenticatorServerException If an error occurred while getting th config value.
     */
    public static String getFIDOAuthenticatorConfig(String key, String tenantDomain)
            throws FIDOAuthenticatorServerException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService =
                    FIDOAuthenticatorServiceDataHolder.getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw new FIDOAuthenticatorServerException(
                    "Error occurred while getting the authenticator configuration", e);
        }
    }

    /**
     * Check whether the account is locked.
     *
     * @param user AuthenticatedUser.
     * @return true if the account is locked.
     * @throws AuthenticationFailedException If an error occurred while checking the account lock status.
     */
    public static boolean isAccountLocked(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return FIDOAuthenticatorServiceDataHolder.getInstance().getAccountLockService().isAccountLocked(
                    user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            String error = String.format(FIDOAuthenticatorConstants.ERROR_GETTING_ACCOUNT_LOCKED_STATE_MESSAGE,
                    FIDOUtil.maskUsernameIfRequired(user.getUserName()));
            throw new AuthenticationFailedException(error, e);
        }
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskUsernameIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    /**
     * To redirect flow to the error page when the user account is locked.
     *
     * @param response The httpServletResponse.
     * @param context  The AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    public static void redirectToErrorPageForLockedUser(HttpServletResponse response,
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            queryParams += FIDOAuthenticatorConstants.ACCOUNT_LOCKED_ERROR_QUERY_PARAMS;
            String errorPage = getErrorPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPage, queryParams);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException(FIDOAuthenticatorConstants.ERROR_REDIRECTING_TO_ERROR_PAGE_MESSAGE, e);
        }
    }

    /**
     * Get FIDO error page URL.
     *
     * @return URL of the FIDO error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getErrorPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create().addPath("authenticationendpoint/" + FIDOAuthenticatorConstants.URI_ERROR).build(
                    IdentityUtil.getHostName()).getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error while building FIDO error page URL", e);
        }
    }
}
