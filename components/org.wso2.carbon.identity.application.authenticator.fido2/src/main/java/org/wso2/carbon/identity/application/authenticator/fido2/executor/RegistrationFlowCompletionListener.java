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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.fido.metadata.MetadataBLOBPayloadEntry;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.UserIdentity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2ExecutorConstants;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Flow execution listener to handle FIDO2 registration flow completion.
 * This listener is triggered when the registration flow is completed.
 */
public class RegistrationFlowCompletionListener extends AbstractFlowExecutionListener {

    private static final Log LOG = LogFactory.getLog(RegistrationFlowCompletionListener.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public int getExecutionOrderId() {

        return 5;
    }

    @Override
    public int getDefaultOrderId() {

        return 5;
    }

    @Override
    public boolean isEnabled() {

        return true;
    }

    @Override
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) {

        if (FIDOUtil.isRegistrationFlow(context) && Constants.STATUS_COMPLETE.equals(step.getFlowStatus())) {
            Object registrationRequestObj = context.getProperty(FIDO2ExecutorConstants.CREDENTIAL_REGISTRATION);
            if (registrationRequestObj == null) {
                return true;
            }
            Map<String, Object> credentialRegistration = mapper.convertValue(registrationRequestObj,
                    new TypeReference<Map<String, Object>>() {
                    });
            try {
                String username = context.getFlowUser().getUsername();
                username = UserCoreUtil.addTenantDomainToEntry(username, context.getTenantDomain());
                FIDO2DeviceStoreDAO.getInstance().addFIDO2RegistrationByUsername(username,
                        buildFromMap(credentialRegistration));
            } catch (FIDO2AuthenticatorServerException e) {
                LOG.error("Error while storing FIDO2 registration for user: " +
                        LoggerUtils.getMaskedContent(context.getFlowUser().getUsername()) + " in flow: " +
                        context.getContextIdentifier(), e);
            }
        }
        return true;
    }

    private static FIDO2CredentialRegistration buildFromMap(Map<String, Object> map) {

        Object credentialObj = map.get(FIDO2ExecutorConstants.CREDENTIAL);
        Object userIdentityObj = map.get(FIDO2ExecutorConstants.RegistrationConstants.USER_IDENTITY);

        RegisteredCredential credential = mapper.convertValue(credentialObj, RegisteredCredential.class);
        UserIdentity userIdentity = mapper.convertValue(userIdentityObj, UserIdentity.class);

        Optional<String> credentialNickname = Optional.ofNullable((String)
                map.get(FIDO2ExecutorConstants.RegistrationConstants.CREDENTIAL_NICKNAME));
        Optional<MetadataBLOBPayloadEntry> attestationMetadata = Optional.ofNullable(
                mapper.convertValue(map.get(FIDO2ExecutorConstants.RegistrationConstants.ATTESTATION_METADATA),
                        MetadataBLOBPayloadEntry.class));

        long signatureCount = map.get(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT) != null ?
                ((Number) map.get(FIDO2ExecutorConstants.RegistrationConstants.SIGNATURE_COUNT)).longValue() : 0;
        String displayName = (String) map.get(FIDO2ExecutorConstants.RegistrationConstants.DISPLAY_NAME);
        boolean isUsernamelessSupported = Boolean.TRUE.equals(
                map.get(FIDO2ExecutorConstants.RegistrationConstants.IS_USERNAMELESS_SUPPORTED));

        Instant registrationTime = null;
        if (map.get(FIDO2ExecutorConstants.RegistrationConstants.REGISTRATION_TIME) != null) {
            registrationTime = Instant.parse((String)
                    map.get(FIDO2ExecutorConstants.RegistrationConstants.REGISTRATION_TIME));
        }

        FIDO2CredentialRegistration registration = FIDO2CredentialRegistration.builder()
                .signatureCount(signatureCount)
                .userIdentity(userIdentity)
                .credentialNickname(credentialNickname)
                .credential(credential)
                .attestationMetadata(attestationMetadata)
                .displayName(displayName)
                .isUsernamelessSupported(isUsernamelessSupported)
                .build();

        if (registrationTime != null) {
            registration = registration.withRegistrationTime(registrationTime);
        }
        return registration;
    }
}
