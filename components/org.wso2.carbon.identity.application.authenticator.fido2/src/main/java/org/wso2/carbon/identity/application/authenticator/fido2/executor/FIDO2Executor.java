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

package org.wso2.carbon.identity.application.authenticator.fido2.executor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.user.registration.engine.Constants;
import org.wso2.carbon.identity.user.registration.engine.graph.Executor;
import org.wso2.carbon.identity.user.registration.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.engine.model.RegistrationContext;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;

public class FIDO2Executor implements Executor {

    private static final WebAuthnService webAuthnService = new WebAuthnService();
    public static final String DISPLAY_NAME_CLAIM_URI = "http://wso2.org/claims/givenname";
    public static final String ORIGIN = "origin";
    public static final String REQUEST_ID = "requestId";
    public static final String CREDENTIAL = "credential";
    public static final String CREDENTIAL_ID = "credentialId";
    public static final String ID = "id";

    @Override
    public String getName() {

        return "FIDO2Executor";
    }

    @Override
    public ExecutorResponse execute(RegistrationContext context) {

        ExecutorResponse response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());

        try {
            String origin = resolveOrigin(context);
            if (StringUtils.isBlank(origin)) {
                return clientInputRequiredResponse(response, ORIGIN);
            }
            context.setProperty(ORIGIN, origin);

            String username = context.getRegisteringUser().getUsername();
            if (StringUtils.isBlank(username)) {
                return errorResponse(response, "Username is required for FIDO2 registration.");
            }

            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

            if (isInitiation(context)) {
                return initiateFIDO2(context, origin, response);
            } else {
                return processFIDO2(context, username, response);
            }
        } catch (JsonProcessingException e) {
            return errorResponse(new ExecutorResponse(), e.getMessage());
        }
    }

    private ExecutorResponse processFIDO2(RegistrationContext context, String username, ExecutorResponse response) {

        String requestId = context.getUserInputData().get(REQUEST_ID);
        String credential = context.getUserInputData().get(CREDENTIAL);

        try {
            if (StringUtils.isNotBlank(requestId) && StringUtils.isNotBlank(credential)) {
                JsonObject challengeResponse = new JsonObject();
                JsonObject credentialObject = (JsonObject) JsonParser.parseString(credential);
                challengeResponse.add(REQUEST_ID, JsonParser.parseString(requestId));
                challengeResponse.add(CREDENTIAL, credentialObject);
                webAuthnService.finishFIDO2Registration(challengeResponse.toString(), username);

                String credentialId = credentialObject.getAsJsonPrimitive(ID).getAsString();
                response.getContextProperties().put(CREDENTIAL_ID, credentialId);
                response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
            }
        } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
            return errorResponse(response, e.getMessage());
        }
        return response;
    }

    private ExecutorResponse initiateFIDO2(RegistrationContext context, String origin, ExecutorResponse response)
            throws JsonProcessingException {

        try {
            String username = context.getRegisteringUser().getUsername();
            String displayName = Optional.ofNullable((String) context.getRegisteringUser()
                    .getClaim(DISPLAY_NAME_CLAIM_URI)).filter(StringUtils::isNotBlank).orElse(username);
            Either<String, FIDO2RegistrationRequest> result = webAuthnService.initiateFIDO2Registration(origin,
                    username, displayName);
            if (result.isRight()) {
                FIDO2RegistrationRequest fidoRequest = result.right().get();
                Map<String, String> additionalInfo = new HashMap<>();
                additionalInfo.put(Constants.INTERACTION_DATA, FIDOUtil.writeJson(fidoRequest));
                response.setAdditionalInfo(additionalInfo);
                response.setResult(Constants.ExecutorStatus.STATUS_INTERACTION);
                response.setRequiredData(Arrays.asList(REQUEST_ID, CREDENTIAL));
            }
        } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
            return errorResponse(response, e.getMessage());
        }

        return response;
    }

    private String resolveOrigin(RegistrationContext context) {

        String origin = context.getUserInputData().get(ORIGIN);
        if (StringUtils.isNotBlank(origin)) {
            context.getProperties().put(ORIGIN, origin);
        } else {
            origin = (String) context.getProperties().get(ORIGIN);
        }
        return origin;
    }

    private boolean isInitiation(RegistrationContext context) {

        String requestId = context.getUserInputData().get(REQUEST_ID);
        String credential = context.getUserInputData().get(CREDENTIAL);
        return StringUtils.isBlank(requestId) || StringUtils.isBlank(credential);
    }

    private ExecutorResponse clientInputRequiredResponse(ExecutorResponse response, String... fields) {

        response.setResult(Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(fields));
        return response;
    }

    private ExecutorResponse errorResponse(ExecutorResponse response, String message) {

        response.setErrorMessage(message);
        response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
        return response;
    }

    @Override
    public List<String> getInitiationData() {

        return Arrays.asList(ORIGIN, USERNAME_CLAIM);
    }

    @Override
    public ExecutorResponse rollback(RegistrationContext context) {

        String credentialId = (String) context.getProperties().get(CREDENTIAL_ID);
        ExecutorResponse response = new ExecutorResponse();
        if (StringUtils.isNotBlank(credentialId) &&
                StringUtils.isNotBlank(context.getRegisteringUser().getUsername())) {
            try {
                webAuthnService.deregisterFIDO2Credential(credentialId, context.getRegisteringUser().getUsername());
            } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
                return errorResponse(new ExecutorResponse(), e.getMessage());
            }
        }
        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }
}
