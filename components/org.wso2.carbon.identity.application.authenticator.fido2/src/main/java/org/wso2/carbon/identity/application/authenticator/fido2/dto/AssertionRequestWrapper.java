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

package org.wso2.carbon.identity.application.authenticator.fido2.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import lombok.NonNull;
import lombok.Value;

import java.util.Optional;

/**
 * Wrapper for FIDO2 finish registration request.
 */
@Value
public class AssertionRequestWrapper {

    @NonNull
    private final ByteArray requestId;

    @NonNull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @NonNull
    private final Optional<String> username;

    @NonNull
    @JsonIgnore
    private final transient com.yubico.webauthn.AssertionRequest request;

    public AssertionRequestWrapper(
        @NonNull
                ByteArray requestId,
        @NonNull
                AssertionRequest request
    ) {
        this.requestId = requestId;
        this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
        this.username = request.getUsername();
        this.request = request;

    }

}
