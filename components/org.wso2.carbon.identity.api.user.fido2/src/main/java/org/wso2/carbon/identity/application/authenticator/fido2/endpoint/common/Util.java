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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.CredentialIdApiServiceImpl.AUTHENTICATED_WITH_BASIC_AUTH;

/**
 * This class includes the utility methods for fido2 endpoint.
 */
public class Util {

    private static final Log LOG = LogFactory.getLog(Util.class);

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

    /**
     * Validate whether a given string is a valid JSON or not.
     *
     * @param jsonString JSON string.
     * @return Returns true if the given value is a valid JSON string.
     */
    public static boolean isValidJson(String jsonString) {

        try {
            new JSONObject(jsonString);
        } catch (JSONException e) {
            try {
                new JSONArray(jsonString);
            } catch (JSONException e1) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidAuthenticationType() {

        /*
        Check whether the request is authenticated with basic auth. FIDO endpoint should not be allowed for basic
        authentication. This approach can be improved by providing a Level of Assurance (LOA) and checking that in
        FIDOAdminService.
         */
        if (Boolean.parseBoolean(
                (String) IdentityUtil.threadLocalProperties.get().get(AUTHENTICATED_WITH_BASIC_AUTH))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Not a valid authentication method. "
                        + "This method is blocked for the requests with basic authentication.");
            }
            return false;
        }
        return true;
    }

}
