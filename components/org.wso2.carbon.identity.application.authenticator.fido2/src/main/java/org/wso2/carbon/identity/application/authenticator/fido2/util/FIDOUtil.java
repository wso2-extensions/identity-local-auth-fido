/*
 * Copyright (c) (2019-2022), WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.fido2.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.JacksonCodecs;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_MDS_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_MDS_SCHEDULER_INITIAL_DELAY;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIDO_MDS_SCHEDULER_INITIAL_DELAY_DEFAULT_VALUE;

/**
 * FIDOUtil class for FIDO authentication component.
 */
public class FIDOUtil {

    private static final ObjectMapper jsonMapper = JacksonCodecs.json();
    private static Boolean metadataValidationsEnabled;
    private static Integer mdsSchedulerInitialDelay;

    private FIDOUtil() {
    }

    public static String writeJson(Object o) throws JsonProcessingException {

        return jsonMapper.writeValueAsString(o);
    }

    public static String getOrigin(HttpServletRequest request) {

        return request.getScheme() + "://" + request.getServerName() + ":" +
                request.getServerPort();
    }

    /**
     * Check whether metadata validations are enabled for the server.
     *
     * @return boolean indicating server mds validation preference.
     */
    public static boolean isMetadataValidationsEnabled() {

        if (metadataValidationsEnabled == null) {
            String mdsEnabled = IdentityUtil.getProperty(FIDO_MDS_ENABLED);

            if (StringUtils.isNotBlank(mdsEnabled)) {
                metadataValidationsEnabled = Boolean.parseBoolean(mdsEnabled);
            } else {
                metadataValidationsEnabled = false;
            }
        }

        return metadataValidationsEnabled;
    }

    public static long getMDSSchedulerInitialDelay() {

        if (mdsSchedulerInitialDelay == null) {
            String initialDelay = IdentityUtil.getProperty(FIDO_MDS_SCHEDULER_INITIAL_DELAY);

            if (StringUtils.isNotBlank(initialDelay)) {
                mdsSchedulerInitialDelay = Integer.parseInt(initialDelay);
            } else {
                mdsSchedulerInitialDelay = FIDO_MDS_SCHEDULER_INITIAL_DELAY_DEFAULT_VALUE;
            }
        }

        return mdsSchedulerInitialDelay;
    }

    public static boolean isRegistrationFlow(FlowExecutionContext context) {

        return org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.REGISTRATION.getType()
                .equals(context.getFlowType());
    }
}
