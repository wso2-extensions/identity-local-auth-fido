/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.service.RealmService;


/**
 * FIDO Authenticator data holder.
 */
public class FIDOAuthenticatorServiceDataHolder {

    private static final Log log = LogFactory.getLog(FIDOAuthenticatorServiceDataHolder.class);
    private static final FIDOAuthenticatorServiceDataHolder instance = new FIDOAuthenticatorServiceDataHolder();
    private BundleContext bundleContext = null;
    private RealmService realmService = null;
    private static IdentityGovernanceService identityGovernanceService;

    private FIDOAuthenticatorServiceDataHolder() {
    }

    public static FIDOAuthenticatorServiceDataHolder getInstance() {

        return instance;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setBundleContext(BundleContext bundleContext) {

        this.bundleContext = bundleContext;
    }

    /**
     * Get Identity Governance service.
     *
     * @return Identity Governance service.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        if (identityGovernanceService == null) {
            throw new RuntimeException("IdentityGovernanceService not available. Component is not started properly.");
        }
        return identityGovernanceService;
    }

    /**
     * Set Identity Governance service.
     *
     * @param identityGovernanceService Identity Governance service.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        FIDOAuthenticatorServiceDataHolder.identityGovernanceService = identityGovernanceService;
    }
}
