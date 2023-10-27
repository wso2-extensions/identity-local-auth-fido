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
package org.wso2.carbon.identity.application.authenticator.fido.util;

import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authenticator.fido.exception.FIDOAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido.internal.FIDOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.servlet.http.HttpServletRequest;

/**
 * FIDOUtil class for FIDO authentication component.
 */
public class FIDOUtil {
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
}
