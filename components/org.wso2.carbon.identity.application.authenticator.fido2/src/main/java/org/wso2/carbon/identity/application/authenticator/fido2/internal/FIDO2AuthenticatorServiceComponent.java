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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.internal;

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
import org.wso2.carbon.identity.application.authenticator.fido2.executor.FIDO2Executor;
import org.wso2.carbon.identity.application.authenticator.fido2.executor.RegistrationFlowCompletionListener;
import org.wso2.carbon.identity.application.authenticator.fido2.listener.FIDO2DeviceAssociatedUserOperationsListener;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.listener.FlowExecutionListener;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_MDS_SCHEDULER_INITIAL_DELAY;

/**
 * OSGI declarative service component which handles registration and unregistration of FIDO2AuthenticatorComponent.
 */
@Component(
        name = "identity.application.authenticator.fido2.component",
        immediate = true
)
public class FIDO2AuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(FIDO2AuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        FIDO2AuthenticatorServiceDataHolder dataHolder = FIDO2AuthenticatorServiceDataHolder.getInstance();
        BundleContext bundleContext = context.getBundleContext();

        try {
            bundleContext.registerService(
                    UserStoreConfigListener.class.getName(), new UserStoreConfigListenerImpl(), null);
            bundleContext.registerService(UserOperationEventListener.class.getName(),
                    new FIDO2DeviceAssociatedUserOperationsListener(), null);
            bundleContext.registerService(Executor.class.getName(), new FIDO2Executor(), null);
            bundleContext.registerService(FlowExecutionListener.class, new RegistrationFlowCompletionListener(), null);
        } catch (Exception e) {
            log.error("Error registering UserStoreConfigListener ", e);
        }

        // Activate metadata initialization task if enabled.
        if (FIDOUtil.isMetadataValidationsEnabled()) {
            FIDO2AuthenticatorServiceDataHolder.getInstance().setMetadataService(new MetadataService());
            MetadataSchedulerService metadataSchedulerService = new MetadataSchedulerService(
                    FIDOUtil.getMDSSchedulerInitialDelay());
            metadataSchedulerService.activateMetadataInitialization();
        }

        dataHolder.setBundleContext(bundleContext);
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Deactivating FIDO2Authenticator bundle...");
        }

        FIDO2AuthenticatorServiceDataHolder.getInstance().setBundleContext(null);
        FIDO2AuthenticatorServiceDataHolder.getInstance().setMetadataService(null);
    }

    public static RealmService getRealmService() {

        return FIDO2AuthenticatorServiceDataHolder.getInstance().getRealmService();
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
            log.debug("Setting the Realm Service in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }

    protected void setMetadataService(MetadataService metadataService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Metadata Service in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setMetadataService(metadataService);
    }

    protected void unsetMetadataService(MetadataService metadataService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Metadata Service in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setMetadataService(null);
    }

    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait
         until identity core is started */
    }

    protected void unsetIdentityCoreInitializedEventService(
            IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait
         until identity core is started */
    }

    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the configuration manager in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setConfigurationManager(configurationManager);
    }

    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the configuration manager in FIDO2 authenticator bundle");
        }
        FIDO2AuthenticatorServiceDataHolder.getInstance().setConfigurationManager(null);
    }
}
