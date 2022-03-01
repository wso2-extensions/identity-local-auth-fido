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

package org.wso2.carbon.identity.application.authenticator.fido2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * FIDO2 Authenticator data holder.
 */
public class FIDO2AuthenticatorServiceDataHolder {

    private static final Log log = LogFactory.getLog(FIDO2AuthenticatorServiceDataHolder.class);
    private static final FIDO2AuthenticatorServiceDataHolder instance = new FIDO2AuthenticatorServiceDataHolder();
    private BundleContext bundleContext = null;
    private RealmService realmService = null;
    private MetadataService metadataService = null;

    private FIDO2AuthenticatorServiceDataHolder() {
    }

    public static FIDO2AuthenticatorServiceDataHolder getInstance() {

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

    public void setMetadataService(MetadataService metadataService) {

        this.metadataService = metadataService;
    }

    public MetadataService getMetadataService() {

        return this.metadataService;
    }
}
