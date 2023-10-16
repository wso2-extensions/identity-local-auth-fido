/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido.connector;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authenticator.fido.util.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * This class contains the authenticator config implementation.
 */
public class FIDOAuthenticatorConfigImpl implements IdentityConnectorConfig {
    @Override
    public String getName() {
        return FIDOAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return FIDOAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {
        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION,
                "Enable usernameless authentication");
        nameMapping.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT,
                "Enable passkey progressive enrollment");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION,
                "Allow users to login without a username");
        descriptionMapping.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT,
                "Allow users to enroll a passkey progressively during the login flow");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION);
        properties.add(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        String enableUsernamelessAuthentication = "false";
        String enablePasskeyProgressiveEnrollment = "true";

        String enableUsernamelessAuthenticationProperty =
                IdentityUtil.getProperty(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION);
        String enablePasskeyProgressiveEnrollmentProperty = IdentityUtil.getProperty(
                FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT);

        if (StringUtils.isNotBlank(enableUsernamelessAuthenticationProperty)) {
            enableUsernamelessAuthentication = enableUsernamelessAuthenticationProperty;
        }
        if (StringUtils.isNotBlank(enablePasskeyProgressiveEnrollmentProperty)) {
            enablePasskeyProgressiveEnrollment = enablePasskeyProgressiveEnrollmentProperty;
        }

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_USERNAMELESS_AUTHENTICATION,
                enableUsernamelessAuthentication);
        defaultProperties.put(FIDOAuthenticatorConstants.ConnectorConfig.ENABLE_PASSKEY_PROGRESSIVE_ENROLLMENT,
                enablePasskeyProgressiveEnrollment);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {
        return null;
    }
}
