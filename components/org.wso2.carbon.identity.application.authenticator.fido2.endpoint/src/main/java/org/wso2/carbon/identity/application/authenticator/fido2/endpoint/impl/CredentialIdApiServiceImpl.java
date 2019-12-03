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
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.CredentialIdApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.FIDO2Constants;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.Util;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;

import javax.ws.rs.core.Response;

/**
 * Provides service implementation for FIDO2 device de-registering.
 */
public class CredentialIdApiServiceImpl extends CredentialIdApiService {

    private static final Log LOG = LogFactory.getLog(CredentialIdApiServiceImpl.class);

    @Override
    public Response credentialIdDelete(String credentialId) {

        try {
            WebAuthnService webAuthnService = new WebAuthnService();
            webAuthnService.deregisterFIDO2Credential(credentialId);
            return Response.ok().build();
        } catch (FIDO2AuthenticatorClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while deleting FIDO2 credentialId: " + credentialId, e);
            }
            if (FIDO2Constants.ErrorMessages.ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE.getCode()
                    .equals(e.getErrorCode())) {
                return Response.status(Response.Status.NOT_FOUND).entity(Util.getErrorDTO(FIDO2Constants.ErrorMessages
                        .ERROR_CODE_DELETE_REGISTRATION_CREDENTIAL_UNAVAILABLE, credentialId)).build();
            }
            return Response.status(Response.Status.BAD_REQUEST).entity(Util.getErrorDTO(FIDO2Constants.ErrorMessages
                    .ERROR_CODE_DELETE_REGISTRATION_INVALID_CREDENTIAL, credentialId)).build();
        } catch (FIDO2AuthenticatorServerException e) {
            LOG.error("Unexpected server exception while deleting FIDO2 credentialId: " + credentialId, e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(Util.getErrorDTO
                    (FIDO2Constants.ErrorMessages.ERROR_CODE_DELETE_CREDENTIALS, credentialId)).build();
        }
    }
}
