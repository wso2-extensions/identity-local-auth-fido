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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuditLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.application.authenticator.fido2.internal.FIDO2AuthenticatorServiceDataHolder;

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
     * @param targetId     The credential ID of the FIDO2 device.
     */
    public void printAuditLog(Operation operation, String username, String targetId) {

        JSONObject data = null;
        try {
            data = createAuditLogEntry(username);
        } catch (UserStoreException e) {
            throw new RuntimeException("Error while retrieving user ID from username.", e);
        }
        buildAuditLog(operation, targetId, data);
    }

    /**
     * Build and trigger the audit log event.
     *
     * @param operation The operation to be logged.
     * @param data      The JSON data payload for the log.
     */
    private void buildAuditLog(Operation operation, String targetId, JSONObject data) {

        AuditLog.AuditLogBuilder auditLogBuilder;
        try {
            auditLogBuilder = new AuditLog.AuditLogBuilder(getInitiatorId(),
                    LoggerUtils.getInitiatorType(getInitiatorId()),
                    targetId,
                    LogConstants.TARGET_TYPE_FIELD,
                    operation.getLogAction()).data(jsonObjectToMap(data));
        } catch (UserStoreException e) {
            throw new RuntimeException("Error while retrieving user ID from username.", e);
        }
        triggerAuditLogEvent(auditLogBuilder);
    }

    /**
     * Create the core JSON data structure for the audit log entry.
     *
     * @param username The username the user associated with the credential.
     * @return A JSONObject containing the audit data.
     */
    private JSONObject createAuditLogEntry(String username) throws UserStoreException {

        JSONObject data = new JSONObject();
        data.put(LogConstants.END_USER_ID, username != null ? resolveUserIdFromUsername(username) : JSONObject.NULL);
        data.put(LogConstants.DEREGISTERED_AT_FIELD, System.currentTimeMillis());

        return data;
    }

    /**
     * To get the current user, who is doing the current task.
     *
     * @return Current logged-in user.
     */
    private String getUser() throws UserStoreException {

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
    private String getInitiatorId() throws UserStoreException {

        String initiator = null;
        String username = getUser();
        String tenantDomain = getUser();
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
     * Resolve user ID from the given username.
     *
     * @param username The fully qualified username.
     * @return The user ID.
     * @throws UserStoreException If an error occurs while retrieving the user ID.
     */
    private String resolveUserIdFromUsername(String username) throws UserStoreException {

        RealmService userRealm = FIDO2AuthenticatorServiceDataHolder.getInstance().getRealmService();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) userRealm
                .getTenantUserRealm(IdentityTenantUtil.getTenantId(tenantDomain)).getUserStoreManager();
        String usernameWithoutDomain = MultitenantUtils.getTenantAwareUsername(username);
        return userStoreManager.getUserIDFromUserName(usernameWithoutDomain);
    }

    /**
     * FIDO2/WebAuthn operations to be logged.
     */
    public enum Operation {

        DEREGISTER_PASSKEY("Deregister-Passkey");

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

        public static final String TARGET_TYPE_FIELD = "Passkey";
        public static final String END_USER_ID = "UserId";
        public static final String DEREGISTERED_AT_FIELD = "DeregisteredAt";
    }
}
