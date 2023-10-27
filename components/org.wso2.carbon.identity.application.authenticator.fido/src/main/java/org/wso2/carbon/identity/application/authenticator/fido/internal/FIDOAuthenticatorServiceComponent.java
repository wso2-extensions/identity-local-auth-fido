/*
 * Copyright (c) (2019-2022), WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.fido.internal;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.fido.FIDOAuthenticator;
import org.wso2.carbon.identity.application.authenticator.fido.connector.FIDOAuthenticatorConfigImpl;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2FService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ServerConstants;

/**
 * OSGI declarative service component which handles registration and unregistration of FIDOAuthenticatorComponent.
 */
@Component(
        name = "identity.application.authenticator.fido.component",
        immediate = true
)
public class FIDOAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(FIDOAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        FIDOAuthenticatorServiceDataHolder dataHolder = FIDOAuthenticatorServiceDataHolder.getInstance();
        BundleContext bundleContext = context.getBundleContext();

        FIDOAuthenticator fidoAuthenticator = FIDOAuthenticator.getInstance();

        try {
            bundleContext.registerService(IdentityConnectorConfig.class.getName(),
                    new FIDOAuthenticatorConfigImpl(), null);
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), fidoAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("FIDOAuthenticator service is registered.");
            }
        } catch (Exception e) {
            log.error("Error registering FIDOAuthenticator service.", e);
        }

        String providerName = ServerConfiguration.getInstance().getFirstProperty(ServerConstants.JCE_PROVIDER);
        if (StringUtils.isBlank(providerName) || providerName.equals(ServerConstants.JCE_PROVIDER_BC)) {
            U2FService u2FService = U2FService.getInstance();
            try {
                bundleContext.registerService(U2FService.class, u2FService, null);
                if (log.isDebugEnabled()) {
                    log.debug("U2FService is registered.");
                }
            } catch (Exception e) {
                log.error("Error registering U2FService.", e);
            }
        }

        try {
            bundleContext.registerService(
                    UserStoreConfigListener.class.getName(), new UserStoreConfigListenerImpl(), null);
        } catch (Exception e) {
            log.error("Error registering UserStoreConfigListener.", e);
        }

        dataHolder.setBundleContext(bundleContext);
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Deactivating FIDOAuthenticator bundle...");
        }

        FIDOAuthenticatorServiceDataHolder.getInstance().setBundleContext(null);
    }

    public static RealmService getRealmService() {

        return FIDOAuthenticatorServiceDataHolder.getInstance().getRealmService();
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service in FIDO authenticator bundle.");
        }
        FIDOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service in FIDO authenticator bundle.");
        }
        FIDOAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        FIDOAuthenticatorServiceDataHolder.setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        FIDOAuthenticatorServiceDataHolder.setIdentityGovernanceService(null);
    }
}
