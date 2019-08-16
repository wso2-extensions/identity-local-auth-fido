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

import org.wso2.carbon.identity.application.common.cache.CacheEntry;

import java.net.URL;

/**
 * FIDO2 cache entry.
 */
public class FIDO2CacheEntry extends CacheEntry {

    private String publicKeyCredentialCreationOptions;
    private URL appId;
    private String assertionRequest;

    public FIDO2CacheEntry(String publicKeyCredentialCreationOptions, String assertionRequest, URL appId) {

        this.publicKeyCredentialCreationOptions = publicKeyCredentialCreationOptions;
        this.appId = appId;
        this.assertionRequest = assertionRequest;
    }

    public String getAssertionRequest() {

        return assertionRequest;
    }

    public String getPublicKeyCredentialCreationOptions() {

        return publicKeyCredentialCreationOptions;
    }

    public URL getOrigin() {

        return appId;
    }
}
