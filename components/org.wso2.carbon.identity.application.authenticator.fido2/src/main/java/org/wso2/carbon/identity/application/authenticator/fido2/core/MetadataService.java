package org.wso2.carbon.identity.application.authenticator.fido2.core;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.FidoMDS3MetadataBLOBProvider;
import com.webauthn4j.metadata.LocalFilesMetadataStatementsProvider;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.anchor.AggregatingTrustAnchorRepository;
import com.webauthn4j.metadata.anchor.MetadataBLOBBasedTrustAnchorRepository;
import com.webauthn4j.metadata.anchor.MetadataStatementsBasedTrustAnchorRepository;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Helper class for FIDO metadata validations.
 */
public class MetadataService {

    private static final Log log = LogFactory.getLog(MetadataService.class);

    private static volatile MetadataService metadataService;
    private ObjectConverter objectConverter;
    private DefaultCertPathTrustworthinessValidator defaultCertPathTrustworthinessValidator;

    private static final Object lock = new Object();

    public  static MetadataService getInstance() {

        if (metadataService == null) {
            synchronized (lock) {
                if (metadataService == null) {
                    metadataService = new MetadataService();
                    metadataService.initializeDefaultCertPathTrustworthinessValidator();
                }
            }
        }

        return metadataService;
    }

    private void initializeDefaultCertPathTrustworthinessValidator() {

        objectConverter = new ObjectConverter();

        // Create URL based MDS BLOB provider.
        MetadataBLOBProvider[] fidoMDS3MetdataBLOBProviders = Stream.of(
                "https://mds3.certinfra.fidoalliance.org/execute/" +
                        "072db810fd6d514f0be968600f0aeb0cfc323349dd91a64e85619f2063e65a1d",
                "https://mds3.certinfra.fidoalliance.org/execute/" +
                        "371d319829f0d9c3fbac22cb3972233f0e8c40d442baa8901c26e7ff75aafe71",
                "https://mds3.certinfra.fidoalliance.org/execute/" +
                        "b69ced87cf464443c0bff40f3eeb431d5f2e6ea3b343079d20af7eab4ce6eee5",
                "https://mds3.certinfra.fidoalliance.org/execute/" +
                        "dd898588fd43034eca9e4ea7038c14984af1e0d7a0618a07919fab146a934161",
                "https://mds3.certinfra.fidoalliance.org/execute/" +
                        "fe8dfd8670a5b4c8c736c46f3bc5ab33954bc2b878c30e94a987d453b26dc6d3"
        ).map(url -> {
            try {
                FidoMDS3MetadataBLOBProvider fidoMDS3MetadataBLOBProvider = new FidoMDS3MetadataBLOBProvider(
                        objectConverter, url, getMDS3RootCertificate()
                );
                // FIDO conformance test env workaround.
                fidoMDS3MetadataBLOBProvider.setRevocationCheckEnabled(false);
//                fidoMDS3MetadataBLOBProvider.refresh();
                return fidoMDS3MetadataBLOBProvider;
            } catch (RuntimeException | FileNotFoundException | CertificateException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception in constructing url based MDS blob provider: " + e.getMessage());
                }
                return null;
            }
        }).filter(Objects::nonNull).toArray(MetadataBLOBProvider[]::new);

        MetadataBLOBBasedTrustAnchorRepository metadataBLOBBasedTrustAnchorRepository =
                new MetadataBLOBBasedTrustAnchorRepository(fidoMDS3MetdataBLOBProviders);

        // Create local file based MDS provider (Requires to provide metadata from json files).
        MetadataStatementsBasedTrustAnchorRepository metadataStatementsBasedTrustAnchorRepository = null;
        try {
            Path[] metadataPaths = Files.list(
                    Paths.get("/Users/user/Documents/fidoMDS3/toolmetadata/metadataStatements")
            ).toArray(Path[]::new);

            LocalFilesMetadataStatementsProvider localFilesMetadataStatementsProvider =
                    new LocalFilesMetadataStatementsProvider(objectConverter, metadataPaths);
            metadataStatementsBasedTrustAnchorRepository = new MetadataStatementsBasedTrustAnchorRepository(
                    localFilesMetadataStatementsProvider
            );
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception in constructing file based MDS blob provider: " + e.getMessage());
            }
        }

        // Construct trust anchor repository.
        TrustAnchorRepository trustAnchorRepository;
        if (metadataStatementsBasedTrustAnchorRepository == null) {
            trustAnchorRepository = metadataBLOBBasedTrustAnchorRepository;
        } else {
            trustAnchorRepository = new AggregatingTrustAnchorRepository(
                    metadataBLOBBasedTrustAnchorRepository,
                    metadataStatementsBasedTrustAnchorRepository
            );
        }

        // Construct certificate trustworthiness validator object.
        defaultCertPathTrustworthinessValidator = new DefaultCertPathTrustworthinessValidator(
                trustAnchorRepository
        );
        defaultCertPathTrustworthinessValidator.setFullChainProhibited(true);
    }

    private X509Certificate getMDS3RootCertificate() throws CertificateException, FileNotFoundException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        FileInputStream fileInputStream = new FileInputStream("/Users/user/Documents/fidoMDS3/MDS3ROOT.crt");
        return (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
    }

    public DefaultCertPathTrustworthinessValidator getDefaultCertPathTrustworthinessValidator() {

        return defaultCertPathTrustworthinessValidator;
    }
}
