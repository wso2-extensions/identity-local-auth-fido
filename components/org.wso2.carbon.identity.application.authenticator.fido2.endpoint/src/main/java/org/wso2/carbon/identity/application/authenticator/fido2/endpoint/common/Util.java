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

package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;

/**
 * This class includes the utility methods for fido2 endpoint.
 */
public class Util {

    /**
     * Returns a generic errorDTO.
     *
     * @param error Enum of the error caused.
     * @param data  Variable arguments to be passed with the error description.
     * @return A generic errorDTO with the specified details.
     */
    public static ErrorDTO getErrorDTO(FIDO2Constants.ErrorMessages error, String... data) {

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(error.getCode());
        if (data != null) {
            errorDTO.setDescription(String.format(error.getDescription(), data));
        } else {
            errorDTO.setDescription(error.getDescription());
        }
        errorDTO.setMessage(error.getMessage());
        return errorDTO;
    }
}
