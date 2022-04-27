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

package org.wso2.carbon.identity.application.authenticator.fido2.dto;

import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;

/**
 * Class to store FIDO2 related tenant specific configurations.
 */
public class FIDO2Configuration {

    private final boolean attestationValidationEnabled;
    private final boolean mdsValidationEnabled;

    public FIDO2Configuration(boolean attestationValidationEnabled, boolean mdsValidationEnabled) {

        this.attestationValidationEnabled = attestationValidationEnabled;
        this.mdsValidationEnabled = mdsValidationEnabled;
    }

    public FIDO2Configuration() {

        this.attestationValidationEnabled = FIDO2AuthenticatorConstants
                .FIDO2_CONFIG_ATTESTATION_VALIDATION_DEFAULT_VALUE;
        this.mdsValidationEnabled = FIDO2AuthenticatorConstants.FIDO2_CONFIG_MDS_VALIDATION_DEFAULT_VALUE;
    }

    /**
     * Check whether webauthn4j attestation validations are enabled for the tenant.
     * By default, this is enabled and tenant admins can store a config to disable it.
     *
     * @return boolean indicating attestation validation preference.
     */
    public boolean isAttestationValidationEnabled() {

        return attestationValidationEnabled;
    }

    /**
     * Check whether webauthn4j metadata validations are enabled for the tenant.
     * By default, this is disabled and tenant admins can store a config to enable it.
     *
     * @return boolean indicating mds validation preference.
     */
    public boolean isMdsValidationEnabled() {

        return mdsValidationEnabled;
    }
}
