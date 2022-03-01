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
