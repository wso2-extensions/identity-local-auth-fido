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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.FinishRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.FIDO2Constants;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.Util;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;

import java.text.MessageFormat;
import javax.ws.rs.core.Response;

/**
 * FinishRegistrationApiServiceImpl class is used to complete FIDO2 device registration.
 */
public class FinishRegistrationApiServiceImpl extends FinishRegistrationApiService {

    private static final Log LOG = LogFactory.getLog(FinishRegistrationApiServiceImpl.class);

    @Override
    public Response finishRegistrationPost(String challengeResponse) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(MessageFormat.format("Received finish registration  challenge response: {0}",
                    challengeResponse));
        }
        try {
            WebAuthnService webAuthnService = new WebAuthnService();
            webAuthnService.finishFIDO2Registration(challengeResponse);
            return Response.ok().entity(challengeResponse).build();
        } catch (FIDO2AuthenticatorClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while FIDO2 device finish registration.", e);
            }
            if (FIDO2Constants.ErrorMessages
                    .ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS.getCode()
                    .equals(e.getErrorCode())) {
                return Response.status(Response.Status.CONFLICT).entity(Util.getErrorDTO(FIDO2Constants.ErrorMessages
                        .ERROR_CODE_FINISH_REGISTRATION_USERNAME_AND_CREDENTIAL_ID_EXISTS)).build();
            }
            return Response.status(Response.Status.BAD_REQUEST).entity(Util.getErrorDTO(FIDO2Constants.ErrorMessages
                    .ERROR_CODE_FINISH_REGISTRATION_INVALID_REQUEST, challengeResponse)).build();
        } catch (FIDO2AuthenticatorServerException e) {
            LOG.error("Unexpected server exception while finishing FIDO2 device registration with challenge " +
                    "response: " + challengeResponse, e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(Util.getErrorDTO(FIDO2Constants
                    .ErrorMessages.ERROR_CODE_FINISH_REGISTRATION)).build();
        }
    }
}
