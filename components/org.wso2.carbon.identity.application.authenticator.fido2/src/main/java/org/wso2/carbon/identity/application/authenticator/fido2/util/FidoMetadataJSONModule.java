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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.data.AttachmentHint;
import com.webauthn4j.data.AuthenticationAlgorithm;
import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.PublicKeyRepresentationFormat;
import com.webauthn4j.data.TransactionConfirmationDisplay;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.statement.VerificationMethodDescriptor;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.toc.StatusReport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.List;

/**
 * Jackson module providing lenient deserializers and mix-in annotations for FIDO MDS metadata.
 * Prevents metadata parsing failures when newer or unknown enum values (such as "none" for attestation types
 * or "smart-card" for attachment hints) are encountered in FIDO Alliance metadata BLOBs.
 */
public class FidoMetadataJSONModule extends SimpleModule {

    private static final Log log = LogFactory.getLog(FidoMetadataJSONModule.class);
    private static final long serialVersionUID = 1L;

    public FidoMetadataJSONModule() {

        super("FidoMetadataJSONModule");
        setMixInAnnotation(MetadataStatement.class, MetadataStatementMixin.class);
        setMixInAnnotation(StatusReport.class, StatusReportMixin.class);
        setMixInAnnotation(VerificationMethodDescriptor.class, VerificationMethodDescriptorMixin.class);
    }

    /**
     * Lenient deserializer for {@link AuthenticatorAttestationType}.
     */
    public static class SafeAuthenticatorAttestationTypeDeserializer
            extends JsonDeserializer<AuthenticatorAttestationType> {

        @Override
        public AuthenticatorAttestationType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return AuthenticatorAttestationType.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown AuthenticatorAttestationType integer value encountered: " + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return AuthenticatorAttestationType.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown AuthenticatorAttestationType string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link AttachmentHint}.
     */
    public static class SafeAttachmentHintDeserializer extends JsonDeserializer<AttachmentHint> {

        @Override
        public AttachmentHint deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return AttachmentHint.create(p.getLongValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown AttachmentHint integer value encountered: " + p.getLongValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return AttachmentHint.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown AttachmentHint string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link AuthenticationAlgorithm}.
     */
    public static class SafeAuthenticationAlgorithmDeserializer extends JsonDeserializer<AuthenticationAlgorithm> {

        @Override
        public AuthenticationAlgorithm deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return AuthenticationAlgorithm.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown AuthenticationAlgorithm integer value encountered: " + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return AuthenticationAlgorithm.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown AuthenticationAlgorithm string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link PublicKeyRepresentationFormat}.
     */
    public static class SafePublicKeyRepresentationFormatDeserializer
            extends JsonDeserializer<PublicKeyRepresentationFormat> {

        @Override
        public PublicKeyRepresentationFormat deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return PublicKeyRepresentationFormat.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown PublicKeyRepresentationFormat integer value encountered: "
                                + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return PublicKeyRepresentationFormat.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown PublicKeyRepresentationFormat string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link KeyProtectionType}.
     */
    public static class SafeKeyProtectionTypeDeserializer extends JsonDeserializer<KeyProtectionType> {

        @Override
        public KeyProtectionType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return KeyProtectionType.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown KeyProtectionType integer value encountered: " + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return KeyProtectionType.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown KeyProtectionType string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link MatcherProtectionType}.
     */
    public static class SafeMatcherProtectionTypeDeserializer extends JsonDeserializer<MatcherProtectionType> {

        @Override
        public MatcherProtectionType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return MatcherProtectionType.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown MatcherProtectionType integer value encountered: " + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return MatcherProtectionType.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown MatcherProtectionType string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link TransactionConfirmationDisplay}.
     */
    public static class SafeTransactionConfirmationDisplayDeserializer
            extends JsonDeserializer<TransactionConfirmationDisplay> {

        @Override
        public TransactionConfirmationDisplay deserialize(JsonParser p, DeserializationContext ctxt)
                throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return TransactionConfirmationDisplay.create(p.getIntValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown TransactionConfirmationDisplay integer value encountered: "
                                + p.getIntValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return TransactionConfirmationDisplay.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown TransactionConfirmationDisplay string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link UserVerificationMethod}.
     */
    public static class SafeUserVerificationMethodDeserializer extends JsonDeserializer<UserVerificationMethod> {

        @Override
        public UserVerificationMethod deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                try {
                    return UserVerificationMethod.create(p.getLongValue());
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown UserVerificationMethod integer value encountered: " + p.getLongValue());
                    }
                    return null;
                }
            }
            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return UserVerificationMethod.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown UserVerificationMethod string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Lenient deserializer for {@link AuthenticatorStatus}.
     */
    public static class SafeAuthenticatorStatusDeserializer extends JsonDeserializer<AuthenticatorStatus> {

        @Override
        public AuthenticatorStatus deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

            String val = p.getValueAsString();
            if (val == null) {
                return null;
            }
            try {
                return AuthenticatorStatus.create(val);
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown AuthenticatorStatus string value encountered: " + val);
                }
                return null;
            }
        }
    }

    /**
     * Mixin for {@link MetadataStatement} to configure safe deserializers for enum lists.
     */
    public abstract static class MetadataStatementMixin {

        @JsonDeserialize(contentUsing = SafeAuthenticatorAttestationTypeDeserializer.class)
        private List<AuthenticatorAttestationType> attestationTypes;

        @JsonDeserialize(contentUsing = SafeAuthenticatorAttestationTypeDeserializer.class)
        public abstract List<AuthenticatorAttestationType> getAttestationTypes();

        @JsonDeserialize(contentUsing = SafeAttachmentHintDeserializer.class)
        private List<AttachmentHint> attachmentHint;

        @JsonDeserialize(contentUsing = SafeAttachmentHintDeserializer.class)
        public abstract List<AttachmentHint> getAttachmentHint();

        @JsonDeserialize(contentUsing = SafeAuthenticationAlgorithmDeserializer.class)
        private List<AuthenticationAlgorithm> authenticationAlgorithms;

        @JsonDeserialize(contentUsing = SafeAuthenticationAlgorithmDeserializer.class)
        public abstract List<AuthenticationAlgorithm> getAuthenticationAlgorithms();

        @JsonDeserialize(contentUsing = SafePublicKeyRepresentationFormatDeserializer.class)
        private List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings;

        @JsonDeserialize(contentUsing = SafePublicKeyRepresentationFormatDeserializer.class)
        public abstract List<PublicKeyRepresentationFormat> getPublicKeyAlgAndEncodings();

        @JsonDeserialize(contentUsing = SafeKeyProtectionTypeDeserializer.class)
        private List<KeyProtectionType> keyProtection;

        @JsonDeserialize(contentUsing = SafeKeyProtectionTypeDeserializer.class)
        public abstract List<KeyProtectionType> getKeyProtection();

        @JsonDeserialize(contentUsing = SafeMatcherProtectionTypeDeserializer.class)
        private List<MatcherProtectionType> matcherProtection;

        @JsonDeserialize(contentUsing = SafeMatcherProtectionTypeDeserializer.class)
        public abstract List<MatcherProtectionType> getMatcherProtection();

        @JsonDeserialize(contentUsing = SafeTransactionConfirmationDisplayDeserializer.class)
        private List<TransactionConfirmationDisplay> tcDisplay;

        @JsonDeserialize(contentUsing = SafeTransactionConfirmationDisplayDeserializer.class)
        public abstract List<TransactionConfirmationDisplay> getTcDisplay();
    }

    /**
     * Mixin for {@link StatusReport} to configure safe deserializer for {@link AuthenticatorStatus}.
     */
    public abstract static class StatusReportMixin {

        @JsonDeserialize(using = SafeAuthenticatorStatusDeserializer.class)
        private AuthenticatorStatus status;

        @JsonDeserialize(using = SafeAuthenticatorStatusDeserializer.class)
        public abstract AuthenticatorStatus getStatus();
    }

    /**
     * Mixin for {@link VerificationMethodDescriptor} to configure safe deserializer for {@link UserVerificationMethod}.
     */
    public abstract static class VerificationMethodDescriptorMixin {

        @JsonDeserialize(using = SafeUserVerificationMethodDeserializer.class)
        private UserVerificationMethod userVerificationMethod;

        @JsonDeserialize(using = SafeUserVerificationMethodDeserializer.class)
        public abstract UserVerificationMethod getUserVerificationMethod();
    }
}

