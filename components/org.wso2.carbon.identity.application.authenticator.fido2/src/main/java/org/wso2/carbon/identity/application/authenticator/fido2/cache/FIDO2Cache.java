/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.fido2.cache;

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * FIDO2 cache to store interim data.
 */
public class FIDO2Cache extends AuthenticationBaseCache<FIDO2CacheKey, FIDO2CacheEntry> {

    private static final String FIDO2_CACHE_NAME = "FIDO2Cache";

    private static volatile FIDO2Cache instance;

    private FIDO2Cache() {

        super(FIDO2_CACHE_NAME, true);
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

        FIDO2CacheEntry fido2CacheEntry = super.getValueFromCache(key);
        if (fido2CacheEntry != null) {
            return fido2CacheEntry;
        } else {
            return getFromSessionStore(key.getRequestId());
        }
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
