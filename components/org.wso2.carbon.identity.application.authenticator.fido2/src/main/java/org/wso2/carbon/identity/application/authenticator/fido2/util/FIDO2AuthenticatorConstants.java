/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.fido2.util;

/**
 * Utils class for FIDO2 Authenticator Constants.
 */
public class FIDO2AuthenticatorConstants {

    private FIDO2AuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "FIDO2Authenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "fido2";
    public static final String AUTHENTICATION_STATUS = "Authentication Failed !";
    public static final String AUTHENTICATION_ERROR_MESSAGE = "No registered device found, Please register your device before sign in.";

    public static final String FIDO_AUTH = "FidoAuth";
    public static final String APP_ID = "AppID";


    public static final String URI_LOGIN = "login.do";
    public static final String URI_FIDO_LOGIN = "fido2-auth.jsp";
    public static final String FIDO_CONFIG_XML = "fido-config.xml";

    public static final String USER_HANDLE = "USER_HANDLE";
    public static final String USER_STORE_DOMAIN = "DOMAIN_NAME";
    public static final String TENANT_ID = "TENANT_ID";
    public static final String USERNAME = "USER_NAME";
    public static final String CREDENTIAL_ID = "CREDENTIAL_ID";
    public static final String PUBLIC_KEY_COSE = "PUBLIC_KEY_COSE";
    public static final String SIGNATURE_COUNT = "SIGNATURE_COUNT";

    public static final String TIME_REGISTERED = "TIME_REGISTERED";
    public static final String USER_IDENTITY = "USER_IDENTITY";
    public static final String TRUSTED_ORIGINS = "FIDOTrustedOrigins.Origin";

    public static final String APPLICATION_NAME = "WSO2 Identity Server";

    public static class SQLQueries {

        private SQLQueries() {
        }

        public static final String GET_CREDENTIAL_ID_BY_USERNAME = "SELECT CREDENTIAL_ID FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ? AND USER_NAME = ?";

        public static final String GET_USER_HANDLE_BY_USERNAME = "SELECT USER_HANDLE FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ? AND USER_NAME = ?";

        public static final String GET_USERNAME_BY_USER_HANDLE = "SELECT TENANT_ID, DOMAIN_NAME , " +
                "USER_NAME FROM FIDO2_DEVICE_STORE WHERE USER_HANDLE = ?";

        public static final String GET_CREDENTIAL_BY_ID_AND_USER_HANDLE = "SELECT PUBLIC_KEY_COSE, SIGNATURE_COUNT " +
                "FROM FIDO2_DEVICE_STORE WHERE CREDENTIAL_ID = ? AND USER_HANDLE = ?";

        public static final String GET_CREDENTIAL_BY_ID = "SELECT PUBLIC_KEY_COSE, SIGNATURE_COUNT, USER_HANDLE " +
                "FROM FIDO2_DEVICE_STORE WHERE CREDENTIAL_ID = ?";

        public static final String GET_DEVICE_REGISTRATION_BY_USERNAME = "SELECT * FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ? AND USER_NAME = ?";

        public static final String GET_DEVICE_REGISTRATION_BY_USERNAME_AND_ID = "SELECT * FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ? AND USER_NAME = ? AND CREDENTIAL_ID = ?";

        public static final String ADD_DEVICE_REGISTRATION_QUERY = "INSERT INTO FIDO2_DEVICE_STORE " +
                "(TENANT_ID, DOMAIN_NAME, USER_NAME, TIME_REGISTERED, USER_HANDLE, CREDENTIAL_ID, PUBLIC_KEY_COSE, " +
                "SIGNATURE_COUNT, USER_IDENTITY ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        public static final String DELETE_DEVICE_REGISTRATION_BY_USERNAME_AND_ID = "DELETE FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ? AND USER_NAME = ? AND CREDENTIAL_ID = ?";

        public static final String UPDATE_DOMAIN_QUERY = "UPDATE FIDO2_DEVICE_STORE SET DOMAIN_NAME = ? " +
                "WHERE DOMAIN_NAME = ? AND TENANT_ID = ?";

        public static final String DELETE_REGISTRATION_BY_DOMAIN_AND_TENANT_ID = "DELETE FROM FIDO2_DEVICE_STORE " +
                "WHERE TENANT_ID = ? AND DOMAIN_NAME = ?";
    }
}

