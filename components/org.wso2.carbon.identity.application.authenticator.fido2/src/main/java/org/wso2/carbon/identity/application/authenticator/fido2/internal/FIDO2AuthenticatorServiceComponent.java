/*
 * Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.fido2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.fido2.core.FIDO2Authenticator;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * @scr.component name="identity.application.authenticator.fido2.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class FIDO2AuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(FIDO2AuthenticatorServiceComponent.class);
    private static RealmService realmService;

    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();

        try {
            FIDO2Authenticator fido2Authenticator = FIDO2Authenticator.getInstance();
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), fido2Authenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("FIDO2Authenticator service is registered");
            }
        } catch (Exception e) {
            log.error("Error registering FIDO2Authenticator service", e);
        }

        try {
            WebAuthnService webAuthnService = WebAuthnService.getInstance();
            bundleContext.registerService(WebAuthnService.class, webAuthnService, null);
            if (log.isDebugEnabled()) {
                log.debug("WebAuthn service is registered");
            }
        } catch (Exception e) {
            log.error("Error registering WebAuthn service", e);
        }

        try {
            bundleContext.registerService(UserStoreConfigListener.class.getName(), new UserStoreConfigListenerImpl(), null);
        } catch (Exception e){
            log.error("Error registering UserStoreConfigListener ", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Deactivating FIDO2Authenticator bundle...");
        }
    }

    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        FIDO2AuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
        FIDO2AuthenticatorServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
