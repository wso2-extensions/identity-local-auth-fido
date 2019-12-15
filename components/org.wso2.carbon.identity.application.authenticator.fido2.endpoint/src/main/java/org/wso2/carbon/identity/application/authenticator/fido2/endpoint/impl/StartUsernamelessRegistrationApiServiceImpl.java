package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.StartUsernamelessRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.FIDO2Constants;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.common.Util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

import javax.ws.rs.core.Response;

public class StartUsernamelessRegistrationApiServiceImpl extends StartUsernamelessRegistrationApiService {

    private static final Log LOG = LogFactory.getLog(StartUsernamelessRegistrationApiServiceImpl.class);

    @Override
    public Response startUsernamelessRegistrationPost(String appId) {

        if (StringUtils.isBlank(appId)) {
            return Response.status(Response.Status.BAD_REQUEST).entity(Util.getErrorDTO
                    (FIDO2Constants.ErrorMessages.ERROR_CODE_START_REGISTRATION_EMPTY_APP_ID)).build();
        }

        try {
            if (appId.contains(FIDO2Constants.EQUAL_OPERATOR)) {
                appId = URLDecoder.decode(appId.split(FIDO2Constants.EQUAL_OPERATOR)[1], IdentityCoreConstants.UTF_8);
            } else if (appId.startsWith("{")) {
                JsonObject jsonObject = new JsonParser().parse(appId).getAsJsonObject();
                appId = jsonObject.get(FIDO2Constants.APP_ID).getAsString();
            }
            WebAuthnService webAuthnService = new WebAuthnService();
            Either<String, FIDO2RegistrationRequest> result = webAuthnService.startFIDO2UsernamelessRegistration(appId);
            if (result.isRight()) {
                return Response.ok().entity(FIDOUtil.writeJson(result.right().get())).build();
            } else {
                return Response.serverError().entity(Util.getErrorDTO
                        (FIDO2Constants.ErrorMessages.ERROR_CODE_START_REGISTRATION, appId)).build();
            }
        } catch (FIDO2AuthenticatorClientException | UnsupportedEncodingException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while starting FIDO2 usernameless device registration with appId: " +
                        appId, e);
            }
            return Response.status(Response.Status.BAD_REQUEST).entity(Util.getErrorDTO
                    (FIDO2Constants.ErrorMessages.ERROR_CODE_START_REGISTRATION_INVALID_ORIGIN, appId)).build();
        } catch (JsonProcessingException e) {
            LOG.error("JsonProcessingException while starting FIDO2 usernameless device registration with appId: " +
                    appId, e);
            return Response.serverError().entity(Util.getErrorDTO
                    (FIDO2Constants.ErrorMessages.ERROR_CODE_START_REGISTRATION, appId)).build();
        }
    }
}
