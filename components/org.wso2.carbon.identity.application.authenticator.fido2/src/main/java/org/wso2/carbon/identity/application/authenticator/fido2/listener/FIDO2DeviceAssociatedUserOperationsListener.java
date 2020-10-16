/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.fido2.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.dao.FIDO2DeviceStoreDAO;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * This is an implementation of the UserOperationEventListener and this is responsible for operations related to users
 * that has FIDO2 device associations.
 */
public class FIDO2DeviceAssociatedUserOperationsListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(FIDO2DeviceAssociatedUserOperationsListener.class);

    @Override
    public int getExecutionOrderId() {

        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 101;
    }

    @Override
    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        if (FIDO2DeviceStoreDAO.isFido2DTOPersistenceSupported()) {
            try {
                String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
                int tenantId = userStoreManager.getTenantId();
                FIDO2DeviceStoreDAO.getInstance().deleteRegistrationsForUser(userName, userStoreDomain, tenantId);
            } catch (FIDO2AuthenticatorServerException e) {
                throw new UserStoreException("Error in deleting device registration for user " + userName, e);
            }
        }
        return true;
    }
}
