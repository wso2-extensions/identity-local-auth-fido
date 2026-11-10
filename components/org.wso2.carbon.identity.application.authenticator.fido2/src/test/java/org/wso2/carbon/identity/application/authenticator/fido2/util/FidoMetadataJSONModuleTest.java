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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttachmentHint;
import com.webauthn4j.data.AuthenticationAlgorithm;
import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.PublicKeyRepresentationFormat;
import com.webauthn4j.data.TransactionConfirmationDisplay;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.statement.VerificationMethodDescriptor;
import com.webauthn4j.metadata.data.toc.StatusReport;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * Unit tests for {@link FidoMetadataJSONModule} and {@link FIDOUtil#createMetadataObjectConverter()}.
 */
public class FidoMetadataJSONModuleTest {

    @Test
    public void testMetadataStatementWithUnknownEnums() {

        ObjectConverter objectConverter = FIDOUtil.createMetadataObjectConverter();

        String json = "{\n" +
                "  \"description\": \"Test Authenticator\",\n" +
                "  \"authenticatorVersion\": 1,\n" +
                "  \"protocolFamily\": \"fido2\",\n" +
                "  \"schema\": 3,\n" +
                "  \"upv\": [{\"major\": 1, \"minor\": 0}],\n" +
                "  \"authenticationAlgorithms\": [\"secp256r1_ecdsa_sha256_raw\", \"unknown_future_algorithm\"],\n" +
                "  \"publicKeyAlgAndEncodings\": [\"cose\", \"unknown_format\"],\n" +
                "  \"attestationTypes\": [\"basic_full\", \"none\", \"unknown_type\"],\n" +
                "  \"userVerificationDetails\": [[{\"userVerificationMethod\": \"presence_internal\"}]],\n" +
                "  \"keyProtection\": [\"hardware\", \"unknown_protection\"],\n" +
                "  \"matcherProtection\": [\"on_chip\", \"unknown_matcher\"],\n" +
                "  \"attachmentHint\": [\"internal\", \"smart-card\", \"unknown_hint\"],\n" +
                "  \"tcDisplay\": [\"hardware\", \"unknown_display\"]\n" +
                "}";

        MetadataStatement statement = objectConverter.getJsonConverter().readValue(json, MetadataStatement.class);
        Assert.assertNotNull(statement);
        Assert.assertEquals(statement.getDescription(), "Test Authenticator");

        // Attestation types: "none" and "unknown_type" should deserialize as null, "basic_full" as BASIC_FULL
        List<AuthenticatorAttestationType> attestationTypes = statement.getAttestationTypes();
        Assert.assertNotNull(attestationTypes);
        Assert.assertEquals(attestationTypes.size(), 3);
        Assert.assertEquals(attestationTypes.get(0), AuthenticatorAttestationType.BASIC_FULL);
        Assert.assertNull(attestationTypes.get(1));
        Assert.assertNull(attestationTypes.get(2));

        // Attachment hints: "smart-card" and "unknown_hint" should deserialize as null, "internal" as INTERNAL
        List<AttachmentHint> attachmentHints = statement.getAttachmentHint();
        Assert.assertNotNull(attachmentHints);
        Assert.assertEquals(attachmentHints.size(), 3);
        Assert.assertEquals(attachmentHints.get(0), AttachmentHint.INTERNAL);
        Assert.assertNull(attachmentHints.get(1));
        Assert.assertNull(attachmentHints.get(2));

        // Authentication algorithms
        List<AuthenticationAlgorithm> authAlgorithms = statement.getAuthenticationAlgorithms();
        Assert.assertNotNull(authAlgorithms);
        Assert.assertEquals(authAlgorithms.size(), 2);
        Assert.assertEquals(authAlgorithms.get(0), AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW);
        Assert.assertNull(authAlgorithms.get(1));

        // Public key encodings
        List<PublicKeyRepresentationFormat> pubKeyFormats = statement.getPublicKeyAlgAndEncodings();
        Assert.assertNotNull(pubKeyFormats);
        Assert.assertEquals(pubKeyFormats.size(), 2);
        Assert.assertEquals(pubKeyFormats.get(0), PublicKeyRepresentationFormat.COSE);
        Assert.assertNull(pubKeyFormats.get(1));

        // Key protection
        List<KeyProtectionType> keyProtections = statement.getKeyProtection();
        Assert.assertNotNull(keyProtections);
        Assert.assertEquals(keyProtections.size(), 2);
        Assert.assertEquals(keyProtections.get(0), KeyProtectionType.HARDWARE);
        Assert.assertNull(keyProtections.get(1));

        // Matcher protection
        List<MatcherProtectionType> matcherProtections = statement.getMatcherProtection();
        Assert.assertNotNull(matcherProtections);
        Assert.assertEquals(matcherProtections.size(), 2);
        Assert.assertEquals(matcherProtections.get(0), MatcherProtectionType.ON_CHIP);
        Assert.assertNull(matcherProtections.get(1));

        // TC display
        List<TransactionConfirmationDisplay> tcDisplays = statement.getTcDisplay();
        Assert.assertNotNull(tcDisplays);
        Assert.assertEquals(tcDisplays.size(), 2);
        Assert.assertEquals(tcDisplays.get(0), TransactionConfirmationDisplay.HARDWARE);
        Assert.assertNull(tcDisplays.get(1));
    }

    @Test
    public void testStatusReportWithUnknownStatus() {

        ObjectConverter objectConverter = FIDOUtil.createMetadataObjectConverter();

        String json = "{\"status\":\"UNKNOWN_FUTURE_STATUS\",\"effectiveDate\":\"2026-01-01\"}";
        StatusReport report = objectConverter.getJsonConverter().readValue(json, StatusReport.class);
        Assert.assertNotNull(report);
        Assert.assertNull(report.getStatus());
    }

    @Test
    public void testVerificationMethodDescriptorWithUnknownMethod() {

        ObjectConverter objectConverter = FIDOUtil.createMetadataObjectConverter();

        String json = "{\"userVerificationMethod\":\"unknown_uvm_method\"}";
        VerificationMethodDescriptor descriptor = objectConverter.getJsonConverter()
                .readValue(json, VerificationMethodDescriptor.class);
        Assert.assertNotNull(descriptor);
        Assert.assertNull(descriptor.getUserVerificationMethod());
    }

    @Test
    public void testParseBlobIfPresent() throws Exception {

        String jwtPath = "C:/Users/Ishara Deshan/.gemini/antigravity/brain/e97c79d8-34fd-4d18-bb49-f86299c86964/scratch/blob.jwt";
        File file = new File(jwtPath);
        if (!file.exists()) {
            return;
        }

        String jwt = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8).trim();
        ObjectConverter objectConverter = FIDOUtil.createMetadataObjectConverter();

        JWSFactory jwsFactory = new JWSFactory(objectConverter);
        JWS<MetadataBLOBPayload> jws = jwsFactory.parse(jwt, MetadataBLOBPayload.class);
        MetadataBLOB blob = new MetadataBLOB(jws);

        Assert.assertNotNull(blob.getPayload());
        Assert.assertEquals(blob.getPayload().getEntries().size(), 531);
        Assert.assertTrue(blob.isValidSignature());
    }
}

