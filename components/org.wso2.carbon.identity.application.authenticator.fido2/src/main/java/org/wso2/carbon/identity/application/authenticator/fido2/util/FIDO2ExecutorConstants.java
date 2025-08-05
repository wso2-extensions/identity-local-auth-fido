/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.fido2.util;

/**
 * Constants for FIDO2 Executor.
 */
public class FIDO2ExecutorConstants {

    private FIDO2ExecutorConstants() {

    }

    public static final String ORIGIN = "origin";
    public static final String REQUEST_ID = "requestId";
    public static final String REQUEST_ID_CONTEXT_KEY = "webAuthnRequestId";
    public static final String CREDENTIAL = "credential";
    public static final String CREDENTIAL_ID = "credentialId";
    public static final String CREDENTIAL_REGISTRATION = "credentialRegistration";
    public static final String ID = "id";
    public static final String ACTION = "action";
    public static final String PUBLIC_KEY_CREDENTIAL_CREATION_OPTIONS = "publicKeyCredentialCreationOptions";

    public static class RegistrationConstants {

        private RegistrationConstants() {

        }

        public static final String USER_IDENTITY = "userIdentity";
        public static final String CREDENTIAL_NICKNAME = "credentialNickname";
        public static final String ATTESTATION_METADATA = "attestationMetadata";
        public static final String SIGNATURE_COUNT = "signatureCount";
        public static final String DISPLAY_NAME = "displayName";
        public static final String IS_USERNAMELESS_SUPPORTED = "isUsernamelessSupported";
        public static final String REGISTRATION_TIME = "registrationTime";
    }

    public static class ActionTypes {

        private ActionTypes() {

        }

        public static final String WEBAUTHN_CREATE = "WEBAUTHN_CREATE";
    }
}
