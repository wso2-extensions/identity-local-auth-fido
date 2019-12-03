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

package org.wso2.carbon.identity.application.authenticator.fido2.dao;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDO2CredentialRegistration;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDO2AuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;

/**
 * FIDO2 DAO.
 */
public class FIDO2DeviceStoreDAO implements CredentialRepository {

    private static final Log log = LogFactory.getLog(FIDO2DeviceStoreDAO.class);

    private static boolean isFIDO2DTOPersistenceStatusChecked = false;
    private  static boolean isFIDO2DTOPersistenceSupported = false;
    private final ObjectMapper jsonMapper = WebAuthnCodecs.json();

    public static FIDO2DeviceStoreDAO getInstance() {
        return new FIDO2DeviceStoreDAO();
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {

        Set<PublicKeyCredentialDescriptor> credentialIds = new HashSet<>();
        User user = User.getUserFromUserName(username);

        if (log.isDebugEnabled()) {
            log.debug("getCredentialIdsForUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_CREDENTIAL_ID_BY_USERNAME);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            resultSet = preparedStatement.executeQuery();

            while(resultSet.next()) {
                ByteArray credentiaId = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .CREDENTIAL_ID));
                credentialIds.add(PublicKeyCredentialDescriptor.builder().id(credentiaId).build());
            }

        } catch (SQLException e) {
            log.error("Error when executing FIDO2 get credential by username SQL : " + FIDO2AuthenticatorConstants
                    .SQLQueries.GET_CREDENTIAL_ID_BY_USERNAME, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return credentialIds;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {

        Optional<ByteArray> userHandle = Optional.empty();
        User user = User.getUserFromUserName(username);

        if (log.isDebugEnabled()) {
            log.debug("getUserHandleForUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_USER_HANDLE_BY_USERNAME);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                userHandle = Optional.of(ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .USER_HANDLE)));
            }

        } catch (SQLException e) {
            log.error("Error when executing FIDO registration SQL : " + FIDO2AuthenticatorConstants.SQLQueries
                    .GET_USER_HANDLE_BY_USERNAME, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return userHandle;
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {

        Optional<String> userName = Optional.empty();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_USERNAME_BY_USER_HANDLE);
            preparedStatement.setString(1, new ByteArray(userHandle.getBytes()).getBase64());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                String tenantDomain = IdentityTenantUtil.getTenantDomain(resultSet.getInt(FIDO2AuthenticatorConstants
                        .TENANT_ID));
                String userStoreDomain = resultSet.getString(FIDO2AuthenticatorConstants.USER_STORE_DOMAIN);
                String name = resultSet.getString(FIDO2AuthenticatorConstants.USERNAME);

                User user = new User();
                user.setTenantDomain(tenantDomain);
                user.setUserStoreDomain(userStoreDomain);
                user.setUserName(name);

                userName = Optional.of(user.toString());
            }

        } catch (SQLException e) {
            log.error("Error when executing FIDO registration SQL : " + FIDO2AuthenticatorConstants.SQLQueries
                    .GET_USERNAME_BY_USER_HANDLE, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return userName;
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {

        Optional<RegisteredCredential> registeredCredential = Optional.empty();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_CREDENTIAL_BY_ID_AND_USER_HANDLE);
            preparedStatement.setString(1, new ByteArray(credentialId.getBytes()).getBase64());
            preparedStatement.setString(2, new ByteArray(userHandle.getBytes()).getBase64());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                String publicKeyCose = resultSet.getString(FIDO2AuthenticatorConstants.PUBLIC_KEY_COSE);
                long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                registeredCredential = Optional.of(
                        RegisteredCredential.builder()
                                .credentialId(credentialId)
                                .userHandle(userHandle)
                                .publicKeyCose(ByteArray.fromBase64(publicKeyCose))
                                .signatureCount(signatureCount)
                                .build()
                );
            }
        } catch (SQLException e) {
            log.error("Error when executing FIDO registration SQL : " + FIDO2AuthenticatorConstants.SQLQueries
                    .GET_CREDENTIAL_BY_ID_AND_USER_HANDLE, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return registeredCredential;
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {

        Set<RegisteredCredential> registeredCredentials = new HashSet<>();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_CREDENTIAL_BY_ID);
            preparedStatement.setString(1, new ByteArray(credentialId.getBytes()).getBase64());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                String userHandle = resultSet.getString(FIDO2AuthenticatorConstants.USER_HANDLE);
                String publicKeyCose = resultSet.getString(FIDO2AuthenticatorConstants.PUBLIC_KEY_COSE);
                long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                registeredCredentials.add(RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(ByteArray.fromBase64(userHandle))
                        .publicKeyCose(ByteArray.fromBase64(publicKeyCose))
                        .signatureCount(signatureCount)
                        .build());
            }
        } catch (SQLException e) {
            log.error("Error when executing FIDO registration SQL : " + FIDO2AuthenticatorConstants.SQLQueries
                    .GET_CREDENTIAL_BY_ID, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return registeredCredentials;
    }

    @Deprecated
    /** @deprecated Please use {@link #addFIDO2RegistrationByUsername(String, FIDO2CredentialRegistration)} instead. */
    public void addRegistrationByUsername(String username, CredentialRegistration reg) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("addRegistrationByUsername inputs {username: " + username +  "}");
        }
        User user = User.getUserFromUserName(username);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .ADD_DEVICE_REGISTRATION_QUERY);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setTimestamp(4, new Timestamp(System.currentTimeMillis()));
            preparedStatement.setString(5, reg.getCredential().getUserHandle().getBase64());
            preparedStatement.setString(6, reg.getCredential().getCredentialId().getBase64());
            preparedStatement.setString(7, reg.getCredential().getPublicKeyCose().getBase64());
            preparedStatement.setLong(8, reg.getCredential().getSignatureCount());
            preparedStatement.setString(9, jsonMapper.writeValueAsString(reg.getUserIdentity()));

            preparedStatement.execute();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }
        } catch (SQLException e) {
            log.error("Error when executing FIDO2 get credential by username SQL : " + FIDO2AuthenticatorConstants
                    .SQLQueries.ADD_DEVICE_REGISTRATION_QUERY, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    /**
     * Persists FIDO2 device registration details against the username.
     *
     * @param username Username.
     * @param reg FIDO2 credentials.
     * @throws FIDO2AuthenticatorServerException
     */
    public void addFIDO2RegistrationByUsername(String username, FIDO2CredentialRegistration reg) throws
            FIDO2AuthenticatorServerException {

        if (log.isDebugEnabled()) {
            log.debug("addRegistrationByUsername inputs {username: " + username +  "}");
        }
        User user = User.getUserFromUserName(username);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .ADD_DEVICE_REGISTRATION_QUERY);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setTimestamp(4, new Timestamp(System.currentTimeMillis()));
            preparedStatement.setString(5, reg.getCredential().getUserHandle().getBase64());
            preparedStatement.setString(6, reg.getCredential().getCredentialId().getBase64());
            preparedStatement.setString(7, reg.getCredential().getPublicKeyCose().getBase64());
            preparedStatement.setLong(8, reg.getCredential().getSignatureCount());
            preparedStatement.setString(9, jsonMapper.writeValueAsString(reg.getUserIdentity()));

            preparedStatement.execute();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }
        } catch (SQLException | IOException e) {
            throw new FIDO2AuthenticatorServerException("Server error occurred while adding FIDO2 device " +
                    "registration for username: " + username, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    @Deprecated
    /** @deprecated Please use {@link #getFIDO2RegistrationsByUsername(String)} instead. */
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {

        User user = User.getUserFromUserName(username);
        List<CredentialRegistration> credentialRegistrations = new ArrayList<>();

        if (log.isDebugEnabled()) {
            log.debug("getRegistrationsByUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_DEVICE_REGISTRATION_BY_USERNAME);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            resultSet = preparedStatement.executeQuery();

            while(resultSet.next()) {
                ByteArray credentialId = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants.CREDENTIAL_ID));
                ByteArray userHandle = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants.USER_HANDLE));
                UserIdentity userIdentity = jsonMapper.readValue(resultSet.getString(FIDO2AuthenticatorConstants.USER_IDENTITY), UserIdentity.class);
                ByteArray publicKeyCose = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants.PUBLIC_KEY_COSE));
                Long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                Timestamp timestamp = resultSet.getTimestamp(FIDO2AuthenticatorConstants.TIME_REGISTERED);

                RegisteredCredential credential = RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(publicKeyCose)
                        .signatureCount(signatureCount)
                        .build();

                CredentialRegistration registration = CredentialRegistration.builder()
                        .attestationMetadata(Optional.empty())
                        .userIdentity(userIdentity)
                        .credential(credential)
                        .credentialNickname(Optional.empty())
                        .registrationTime(timestamp.toInstant())
                        .build();

                credentialRegistrations.add(registration);
            }
        } catch (SQLException | IOException e) {
            log.error("Error when executing FIDO2 get credential by username SQL : " + FIDO2AuthenticatorConstants
                    .SQLQueries.GET_DEVICE_REGISTRATION_BY_USERNAME, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return credentialRegistrations;
    }

    /**
     * Retrieve FIDO2 registration details via the username.
     *
     * @param username Username
     * @return A collection of FIDO2 registrations available for a user.
     * @throws FIDO2AuthenticatorServerException
     */
    public Collection<FIDO2CredentialRegistration> getFIDO2RegistrationsByUsername(String username) throws
            FIDO2AuthenticatorServerException {

        User user = User.getUserFromUserName(username);
        List<FIDO2CredentialRegistration> credentialRegistrations = new ArrayList<>();

        if (log.isDebugEnabled()) {
            log.debug("getRegistrationsByUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_DEVICE_REGISTRATION_BY_USERNAME);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            resultSet = preparedStatement.executeQuery();

            while(resultSet.next()) {
                ByteArray credentialId = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .CREDENTIAL_ID));
                ByteArray userHandle = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .USER_HANDLE));
                UserIdentity userIdentity = jsonMapper.readValue(resultSet.getString(FIDO2AuthenticatorConstants.
                        USER_IDENTITY), UserIdentity.class);
                ByteArray publicKeyCose = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .PUBLIC_KEY_COSE));
                Long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                Timestamp timestamp = resultSet.getTimestamp(FIDO2AuthenticatorConstants.TIME_REGISTERED);

                RegisteredCredential credential = RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(publicKeyCose)
                        .signatureCount(signatureCount)
                        .build();

                FIDO2CredentialRegistration registration = FIDO2CredentialRegistration.builder()
                        .attestationMetadata(Optional.empty())
                        .userIdentity(userIdentity)
                        .credential(credential)
                        .credentialNickname(Optional.empty())
                        .registrationTime(timestamp.toInstant())
                        .build();

                credentialRegistrations.add(registration);
            }
        } catch (SQLException | IOException e) {
            throw new FIDO2AuthenticatorServerException("Server error occurred while retrieving FIDO2 device " +
                    "registration for username: " + username, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return credentialRegistrations;
    }

    @Deprecated
    /** @deprecated Please use {@link #getFIDO2RegistrationByUsernameAndCredentialId(String, ByteArray)} instead. */
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username,
                                                                                     ByteArray credentialId) {

        User user = User.getUserFromUserName(username);
        Optional<CredentialRegistration> credentialRegistration = Optional.empty();

        if (log.isDebugEnabled()) {
            log.debug("getRegistrationByUsernameAndCredentialId inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_DEVICE_REGISTRATION_BY_USERNAME_AND_ID);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setString(4, credentialId.getBase64());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                ByteArray userHandle = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants.USER_HANDLE));
                UserIdentity userIdentity = jsonMapper.readValue(resultSet.getString(FIDO2AuthenticatorConstants.USER_IDENTITY), UserIdentity.class);
                ByteArray publicKeyCose = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants.PUBLIC_KEY_COSE));
                Long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                Timestamp timestamp = resultSet.getTimestamp(FIDO2AuthenticatorConstants.TIME_REGISTERED);

                RegisteredCredential credential = RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(publicKeyCose)
                        .signatureCount(signatureCount)
                        .build();

                CredentialRegistration registration = CredentialRegistration.builder()
                        .attestationMetadata(Optional.empty())
                        .userIdentity(userIdentity)
                        .credential(credential)
                        .credentialNickname(Optional.empty())
                        .registrationTime(timestamp.toInstant())
                        .build();
                credentialRegistration = Optional.of(registration);
            }

        } catch (SQLException | IOException e) {
            log.error("Error when executing FIDO2 get credential by username SQL : " + FIDO2AuthenticatorConstants
                    .SQLQueries.GET_DEVICE_REGISTRATION_BY_USERNAME_AND_ID, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return credentialRegistration;
    }

    /**
     * Retrieve FIDO2 device registration information matching a particular username and credential ID.
     *
     * @param username Username.
     * @param credentialId Credential ID.
     * @return FIDO2 registrations for a given username and credential ID combination.
     * @throws FIDO2AuthenticatorServerException
     */
    public Optional<FIDO2CredentialRegistration> getFIDO2RegistrationByUsernameAndCredentialId
            (String username, ByteArray credentialId) throws FIDO2AuthenticatorServerException {

        User user = User.getUserFromUserName(username);
        Optional<FIDO2CredentialRegistration> credentialRegistration = Optional.empty();

        if (log.isDebugEnabled()) {
            log.debug("getRegistrationByUsernameAndCredentialId inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .GET_DEVICE_REGISTRATION_BY_USERNAME_AND_ID);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setString(4, credentialId.getBase64());
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                ByteArray userHandle = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .USER_HANDLE));
                UserIdentity userIdentity = jsonMapper.readValue(resultSet.getString(FIDO2AuthenticatorConstants
                        .USER_IDENTITY), UserIdentity.class);
                ByteArray publicKeyCose = ByteArray.fromBase64(resultSet.getString(FIDO2AuthenticatorConstants
                        .PUBLIC_KEY_COSE));
                Long signatureCount = resultSet.getLong(FIDO2AuthenticatorConstants.SIGNATURE_COUNT);
                Timestamp timestamp = resultSet.getTimestamp(FIDO2AuthenticatorConstants.TIME_REGISTERED);

                RegisteredCredential credential = RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(publicKeyCose)
                        .signatureCount(signatureCount)
                        .build();

                FIDO2CredentialRegistration registration = FIDO2CredentialRegistration.builder()
                        .attestationMetadata(Optional.empty())
                        .userIdentity(userIdentity)
                        .credential(credential)
                        .credentialNickname(Optional.empty())
                        .registrationTime(timestamp.toInstant())
                        .build();
                credentialRegistration = Optional.of(registration);
            }

        } catch (SQLException | IOException e) {
            throw new FIDO2AuthenticatorServerException("Server error occurred while retrieving FIDO2 device " +
                    "registration for username: " + username, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return credentialRegistration;
    }

    @Deprecated
    /** @deprecated Please use {@link #removeFIDO2RegistrationByUsername(String, FIDO2CredentialRegistration)} instead. */
    public void removeRegistrationByUsername(String username, CredentialRegistration registration) {

        User user = User.getUserFromUserName(username);

        if (log.isDebugEnabled()) {
            log.debug("removeRegistrationByUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .DELETE_DEVICE_REGISTRATION_BY_USERNAME_AND_ID);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setString(4, registration.getCredential().getCredentialId().getBase64());

            preparedStatement.execute();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }

        } catch (SQLException e) {
            log.error("Error when executing FIDO2 get credential by username SQL : " + FIDO2AuthenticatorConstants
                    .SQLQueries.DELETE_DEVICE_REGISTRATION_BY_USERNAME_AND_ID, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
    }

    /**
     * Deregister FIDO2 device for a user.
     *
     * @param username Username.
     * @param registration FIDO2 credentials.
     * @throws FIDO2AuthenticatorServerException
     */
    public void removeFIDO2RegistrationByUsername(String username, FIDO2CredentialRegistration registration) throws
            FIDO2AuthenticatorServerException {

        User user = User.getUserFromUserName(username);

        if (log.isDebugEnabled()) {
            log.debug("removeRegistrationByUsername inputs {username: " + user +  "}");
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .DELETE_DEVICE_REGISTRATION_BY_USERNAME_AND_ID);
            preparedStatement.setInt(1, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
            preparedStatement.setString(2, user.getUserStoreDomain());
            preparedStatement.setString(3, user.getUserName());
            preparedStatement.setString(4, registration.getCredential().getCredentialId().getBase64());

            preparedStatement.execute();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }

        } catch (SQLException e) {
            throw new FIDO2AuthenticatorServerException("Server error occurred while de-registering fido device.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
    }

    @Deprecated
    /** @deprecated Please use {@link #updateFIDO2SignatureCount(AssertionResult)} instead. */
    public void updateSignatureCount(AssertionResult result) {

        CredentialRegistration registration = getRegistrationByUsernameAndCredentialId(result.getUsername(), result
                .getCredentialId()).orElseThrow(() -> new NoSuchElementException(String.format(
                "Credential \"%s\" is not registered to user \"%s\"",
                result.getCredentialId(), result.getUsername()
        )));
        removeRegistrationByUsername(result.getUsername(), registration);
        registration.withSignatureCount(result.getSignatureCount());
        try {
            addRegistrationByUsername(result.getUsername(), registration);
        } catch (IOException e) {
            log.error("IOException while updating signature count.", e);
        }
    }

    /**
     * Updates FIDO2 signature count.
     *
     * @param result Assertion result.
     * @throws FIDO2AuthenticatorServerException
     */
    public void updateFIDO2SignatureCount(AssertionResult result) throws FIDO2AuthenticatorServerException {

        FIDO2CredentialRegistration registration = getFIDO2RegistrationByUsernameAndCredentialId(result.getUsername(),
                result.getCredentialId()).orElseThrow(() -> new NoSuchElementException(String.format(
                        "Credential \"%s\" is not registered to user \"%s\"",
                        result.getCredentialId(), result.getUsername()
                )));
        removeFIDO2RegistrationByUsername(result.getUsername(), registration);
        registration.withSignatureCount(result.getSignatureCount());
        addFIDO2RegistrationByUsername(result.getUsername(), registration);
    }

    public void updateDomainNameOfRegistration(int tenantId, String currentUserStoreName, String newUserStoreName)
            throws FIDO2AuthenticatorServerException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries.UPDATE_DOMAIN_QUERY);
            preparedStatement.setString(1, newUserStoreName);
            preparedStatement.setString(2, currentUserStoreName);
            preparedStatement.setInt(3, tenantId);

            preparedStatement.executeUpdate();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }

        } catch (SQLException e) {
            throw new FIDO2AuthenticatorServerException("Could not update the userstore domain : " + currentUserStoreName, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    public void deleteRegistrationFromDomain(int tenantId, String userStoreName)
            throws FIDO2AuthenticatorServerException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement preparedStatement = null;

        try {
            preparedStatement = connection.prepareStatement(FIDO2AuthenticatorConstants.SQLQueries
                    .DELETE_REGISTRATION_BY_DOMAIN_AND_TENANT_ID);
            preparedStatement.setInt(1, tenantId);
            preparedStatement.setString(2, userStoreName);

            preparedStatement.execute();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }

        } catch (SQLException e) {
            throw new FIDO2AuthenticatorServerException(MessageFormat.format("Could not delete registrations" +
                    " that belong to userstore domain : {0} and tenantID : {1}", userStoreName, tenantId), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    public static boolean isFido2DTOPersistenceSupported() {

        if (!isFIDO2DTOPersistenceStatusChecked) {
            ResultSet rs = null;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

                DatabaseMetaData metaData = connection.getMetaData();
                rs = metaData.getTables(null, null, FIDO2AuthenticatorConstants.FIDO2_DEVICE_STORE, null);
                if (rs.next()) {
                    isFIDO2DTOPersistenceSupported = true;
                }
            } catch (SQLException e) {
                log.error("Error in fetching metadata from FIDO2_DEVICE_STORE database", e);
            } finally {
                IdentityDatabaseUtil.closeResultSet(rs);
            }
            isFIDO2DTOPersistenceStatusChecked = true;
        }
        return isFIDO2DTOPersistenceSupported;
    }
}
