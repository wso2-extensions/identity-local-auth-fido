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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import lombok.EqualsAndHashCode;
import lombok.Value;

/**
 * Wrapper for FIDO2 registration request.
 *
 * @deprecated Please use {@link FIDO2RegistrationRequest} class instead.
 */
@Deprecated
@Value
@EqualsAndHashCode(callSuper = false)
public class RegistrationRequest {

    @JsonProperty("username")
    String username;

    @JsonProperty("requestId")
    ByteArray requestId;

    @JsonProperty("publicKeyCredentialCreationOptions")
    PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

}
