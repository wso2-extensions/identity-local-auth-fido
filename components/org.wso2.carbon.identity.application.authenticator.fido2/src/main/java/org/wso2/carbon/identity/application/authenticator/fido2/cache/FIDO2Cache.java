package org.wso2.carbon.identity.application.authenticator.fido2.cache;

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

public class FIDO2Cache extends BaseCache<FIDO2CacheKey, FIDO2CacheEntry> {

    private static final String FIDO2_CACHE_NAME = "FIDO2Cache";

    private static volatile FIDO2Cache instance;

    private FIDO2Cache() {

        super(FIDO2_CACHE_NAME);
    }

    public static FIDO2Cache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (FIDO2Cache.class) {
                if (instance == null) {
                    instance = new FIDO2Cache();
                }
            }
        }
        return instance;
    }

    public void addToCacheByRequestId(FIDO2CacheKey key, FIDO2CacheEntry entry) {

        super.addToCache(key, entry);
        storeToSessionStore(key.getRequestId(), entry);

    }

    public void addToCacheByRequestWrapperId(FIDO2CacheKey key, FIDO2CacheEntry entry) {

        super.addToCache(key, entry);
        storeToSessionStore(key.getRequestId(), entry);

    }

    public FIDO2CacheEntry getValueFromCacheByRequestId(FIDO2CacheKey key) {

        return getFromSessionStore(key.getRequestId());
    }

    public void clearCacheEntryByRequestId(FIDO2CacheKey key) {

        super.clearCacheEntry(key);
        clearFromSessionStore(key.getRequestId());
    }

    private void clearFromSessionStore(String id) {

        SessionDataStore.getInstance().clearSessionData(id, FIDO2_CACHE_NAME);
    }

    private FIDO2CacheEntry getFromSessionStore(String id) {

        return (FIDO2CacheEntry) SessionDataStore.getInstance().getSessionData(id, FIDO2_CACHE_NAME);
    }

    private void storeToSessionStore(String id, FIDO2CacheEntry entry) {

        SessionDataStore.getInstance().storeSessionData(id, FIDO2_CACHE_NAME, entry);
    }
}
