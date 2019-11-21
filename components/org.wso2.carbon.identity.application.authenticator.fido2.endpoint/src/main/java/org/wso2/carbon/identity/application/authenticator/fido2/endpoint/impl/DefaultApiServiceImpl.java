/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.DefaultApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.Constants;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.text.MessageFormat;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.Util.getErrorDTO;

/**
 * DefaultApiServiceImpl class is used to obtain FIDO2 metadata.
 */
public class DefaultApiServiceImpl extends DefaultApiService {

    private static final Log LOG = LogFactory.getLog(DefaultApiServiceImpl.class);

    @Override
    public Response rootGet() {

        try {
            String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String tenantAwareUsername = UserCoreUtil.addTenantDomainToEntry(username, tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug(MessageFormat.format("Fetching device metadata for the username: {0}",
                        tenantAwareUsername));
            }
            WebAuthnService service = new WebAuthnService();
            return Response.ok().entity(FIDOUtil.writeJson(service.getDeviceMetaData(tenantAwareUsername))).build();
        } catch (JsonProcessingException | FIDO2AuthenticatorServerException e) {
            LOG.error(e.getMessage());
            return Response.serverError().entity(getErrorDTO(Constants.ErrorMessages
                    .ERROR_CODE_FETCH_CREDENTIALS)).build();
        }
    }
}
