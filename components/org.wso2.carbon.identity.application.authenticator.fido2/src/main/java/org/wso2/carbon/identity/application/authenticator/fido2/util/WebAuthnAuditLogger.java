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

package org.wso2.carbon.identity.application.authenticator.fido2.util;

import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuditLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils.jsonObjectToMap;
import static org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils.triggerAuditLogEvent;

/**
 * A utility class for handling FIDO2 (WebAuthn) related audit logging.
 */
public class WebAuthnAuditLogger {

    /**
     * Print a FIDO2 audit log for a specific operation.
     *
     * @param operation    The operation being performed (e.g., REGISTER_DEVICE).
     * @param username     The fully qualified username of the user being acted upon.
     * @param credentialId The credential ID of the FIDO2 device.
     * @param initiator    The initiator of the operation.
     */
    public void printAuditLog(Operation operation, String username, String credentialId, String initiator) {

        JSONObject data = createAuditLogEntry(username, credentialId, initiator);
        buildAuditLog(operation, data);
    }

    /**
     * Build and trigger the audit log event.
     *
     * @param operation The operation to be logged.
     * @param data      The JSON data payload for the log.
     */
    private void buildAuditLog(Operation operation, JSONObject data) {

        AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(getInitiatorId(),
                LoggerUtils.getInitiatorType(getInitiatorId()),
                LoggerUtils.Initiator.System.name(),
                LogConstants.TARGET_FIDO_DEVICE,
                operation.getLogAction()).
                data(jsonObjectToMap(data));
        triggerAuditLogEvent(auditLogBuilder);
    }

    /**
     * Create the core JSON data structure for the audit log entry.
     *
     * @param username     The username associated with the credential.
     * @param credentialId The credential ID.
     * @param initiator The initiator of the operation.
     * @return A JSONObject containing the audit data.
     */
    private JSONObject createAuditLogEntry(String username, String credentialId, String initiator) {

        JSONObject data = new JSONObject();
        data.put(LogConstants.USERNAME_FIELD, username!= null? username : JSONObject.NULL);
        data.put(LogConstants.CREDENTIAL_ID_FIELD, credentialId!= null? credentialId : JSONObject.NULL);
        data.put(LogConstants.INITIATOR, initiator != null ? initiator : JSONObject.NULL);

        return data;
    }

    /**
     * To get the current user, who is doing the current task.
     *
     * @return Current logged-in user.
     */
    private String getUser() {

        String user = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isNotEmpty(user)) {
            user = UserCoreUtil.addTenantDomainToEntry(user, CarbonContext.getThreadLocalCarbonContext()
                    .getTenantDomain());
        } else {
            user = CarbonConstants.REGISTRY_SYSTEM_USERNAME;
        }

        return user;
    }

    /**
     * Get the initiator for audit logs.
     *
     * @return Initiator id despite masking.
     */
    private String getInitiatorId() {

        String initiator = null;
        String username = MultitenantUtils.getTenantAwareUsername(getUser());
        String tenantDomain = MultitenantUtils.getTenantDomain(getUser());
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(tenantDomain)) {
            initiator = IdentityUtil.getInitiatorId(username, tenantDomain);
        }
        if (StringUtils.isBlank(initiator)) {
            if (username.equals(CarbonConstants.REGISTRY_SYSTEM_USERNAME)) {
                // If the initiator is wso2.system, we need not mask the username.
                return LoggerUtils.Initiator.System.name();
            }
            initiator = LoggerUtils.getMaskedContent(getUser());
        }

        return initiator;
    }

    /**
     * FIDO2/WebAuthn operations to be logged.
     */
    public enum Operation {
        DEREGISTER_DEVICE("deregister-device");

        private final String logAction;

        Operation(String logAction) {
            this.logAction = logAction;
        }

        public String getLogAction() {
            return this.logAction;
        }
    }

    /**
     * FIDO2/WebAuthn related log constants.
     */
    private static class LogConstants {

        public static final String TARGET_FIDO_DEVICE = "FidoDevice";
        public static final String USERNAME_FIELD = "Username";
        public static final String CREDENTIAL_ID_FIELD = "CredentialId";
        public static final String INITIATOR = "Initiator";
    }
}
