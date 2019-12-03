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

import com.yubico.webauthn.AssertionRequest;
import lombok.Value;

import java.util.Collection;
import java.util.List;

/**
 * Wrapper for successful authentication result.
 */
@Value
public class SuccessfulAuthenticationResult {

    final boolean success = true;
    AssertionRequest request;
    AssertionResponse response;
    Collection<FIDO2CredentialRegistration> registrations;
    List<String> warnings;
}
