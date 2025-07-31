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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.internal.util.JacksonCodecs;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.core.WebAuthnService;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2RegistrationRequest;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.Either;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2ExecutorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.DISPLAY_NAME_CLAIM_URL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.FIRST_NAME_CLAIM_URL;
import static org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants.LAST_NAME_CLAIM_URL;

/**
 * FIDO2 Executor for handling FIDO2 registration and authentication flows.
 */
public class FIDO2Executor implements Executor {

    private static final WebAuthnService webAuthnService = new WebAuthnService();

    @Override
    public String getName() {

        return "FIDO2Executor";
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        ExecutorResponse response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());

        try {
            String origin = resolveOrigin(context);
            if (StringUtils.isBlank(origin)) {
                return clientInputRequiredResponse(response, FIDO2ExecutorConstants.ORIGIN);
            }
            context.setProperty(FIDO2ExecutorConstants.ORIGIN, origin);

            String username = context.getFlowUser().getUsername();
            if (StringUtils.isBlank(username)) {
                return errorResponse(response, "Username is required for WebAuthn registration.");
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

    private ExecutorResponse processFIDO2(FlowExecutionContext context, String username, ExecutorResponse response) {

        String requestId = (String) context.getProperty(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY);
        String credential = context.getUserInputData().get(FIDO2ExecutorConstants.CREDENTIAL);

        try {
            if (StringUtils.isNotBlank(requestId) && StringUtils.isNotBlank(credential)) {
                JsonObject challengeResponse = new JsonObject();
                JsonObject credentialObject = (JsonObject) JsonParser.parseString(credential);
                challengeResponse.add(FIDO2ExecutorConstants.REQUEST_ID, JsonParser.parseString(requestId));
                challengeResponse.add(FIDO2ExecutorConstants.CREDENTIAL, credentialObject);
                // Add tenant domain to the username.
                username = UserCoreUtil.addTenantDomainToEntry(username, context.getTenantDomain());
                if (FIDOUtil.isRegistrationFlow(context)) {
                    FIDO2CredentialRegistration registration = webAuthnService
                            .createFIDO2Credential(challengeResponse.toString(), username);
                    response.getContextProperties()
                            .put(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION, toMap(registration));
                } else {
                    webAuthnService.finishFIDO2Registration(challengeResponse.toString(), username);
                }
                response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
            }
        } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
            return errorResponse(response, e.getMessage());
        }
        return response;
    }

    private ExecutorResponse initiateFIDO2(FlowExecutionContext context, String origin, ExecutorResponse response)
            throws JsonProcessingException {

        try {
            String username = context.getFlowUser().getUsername();
            String displayName = getUserDisplayName(context);
            Either<String, FIDO2RegistrationRequest> result = webAuthnService.initiateFIDO2Registration(origin,
                    username, displayName);
            if (result.isRight()) {
                FIDO2RegistrationRequest fidoRequest = result.right().get();
                Map<String, String> additionalInfo = new HashMap<>();
                Map<String, Object> webAuthnData = new HashMap<>();
                webAuthnData.put(FIDO2ExecutorConstants.ACTION, FIDO2ExecutorConstants.ActionTypes.WEBAUTHN_CREATE);
                webAuthnData.put(FIDO2ExecutorConstants.PUBLIC_KEY_CREDENTIAL_CREATION_OPTIONS,
                        fidoRequest.getPublicKeyCredentialCreationOptions());
                additionalInfo.put(Constants.WEBAUTHN_DATA, FIDOUtil.writeJson(webAuthnData));
                response.setAdditionalInfo(additionalInfo);
                response.getContextProperties().put(FIDO2ExecutorConstants.REQUEST_ID_CONTEXT_KEY,
                        FIDOUtil.writeJson(fidoRequest.getRequestId()));
                response.setResult(Constants.ExecutorStatus.STATUS_WEBAUTHN);
                response.setRequiredData(Arrays.asList(FIDO2ExecutorConstants.CREDENTIAL));
            }
        } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
            return errorResponse(response, e.getMessage());
        }

        return response;
    }

    private String getUserDisplayName(FlowExecutionContext flowExecutionContext) throws FIDO2AuthenticatorServerException {

        String displayName = (String) flowExecutionContext.getFlowUser().getClaim(DISPLAY_NAME_CLAIM_URL);
        // If the displayName is not available, build the displayName with firstName and lastName.
        if (StringUtils.isBlank(displayName)) {
            String firstName = (String) flowExecutionContext.getFlowUser().getClaim(FIRST_NAME_CLAIM_URL);
            String lastName = (String) flowExecutionContext.getFlowUser().getClaim(LAST_NAME_CLAIM_URL);
            if (StringUtils.isNotBlank(firstName) || StringUtils.isNotBlank(lastName)) {
                displayName = StringUtils.join(new String[]{firstName, lastName}, " ");
            } else {
                // If the firstName or the lastName is not available, set the username as the displayName.
                displayName = flowExecutionContext.getFlowUser().getUsername();
            }
        }
        return StringUtils.trim(displayName);
    }

    private String resolveOrigin(FlowExecutionContext context) {

        String origin = context.getUserInputData().get(FIDO2ExecutorConstants.ORIGIN);
        if (StringUtils.isNotBlank(origin)) {
            context.getProperties().put(FIDO2ExecutorConstants.ORIGIN, origin);
        } else {
            origin = (String) context.getProperties().get(FIDO2ExecutorConstants.ORIGIN);
        }
        return origin;
    }

    private boolean isInitiation(FlowExecutionContext context) {

        String credential = context.getUserInputData().get(FIDO2ExecutorConstants.CREDENTIAL);
        return StringUtils.isBlank(credential);
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

        return Arrays.asList(FIDO2ExecutorConstants.ORIGIN, USERNAME_CLAIM);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        String credentialId = (String) context.getProperties().get(FIDO2ExecutorConstants.CREDENTIAL_ID);
        ExecutorResponse response = new ExecutorResponse();
        if (StringUtils.isNotBlank(credentialId) &&
                StringUtils.isNotBlank(context.getFlowUser().getUsername())) {
            try {
                webAuthnService.deregisterFIDO2Credential(credentialId, context.getFlowUser().getUsername());
            } catch (FIDO2AuthenticatorServerException | FIDO2AuthenticatorClientException e) {
                return errorResponse(new ExecutorResponse(), e.getMessage());
            }
        }
        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }

    private static Map<String, Object> toMap(FIDO2CredentialRegistration original) {

        ObjectMapper mapper = JacksonCodecs.json();
        return mapper.convertValue(original, new TypeReference<Map<String, Object>>() {
        });
    }
}
