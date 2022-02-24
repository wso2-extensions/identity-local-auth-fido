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

        // URL based blob provider.
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
                        objectConverter,
                        url,
                        getMDS3RootCertificate()
                );
                // FIDO conformance test env workaround.
                fidoMDS3MetadataBLOBProvider.setRevocationCheckEnabled(false);
//                fidoMDS3MetadataBLOBProvider.refresh();
                return fidoMDS3MetadataBLOBProvider;
            } catch (RuntimeException | FileNotFoundException | CertificateException e) {
                return null;
            }
        }).filter(Objects::nonNull).toArray(MetadataBLOBProvider[]::new);
        /////////////////////////////////////////////////////

//        // File based blob provider.
//        MetadataBLOBProvider[] fidoMDS3MetdataBLOBProviders = Stream.of(
//                "/Users/user/Documents/fidoMDS3/072db810fd6d514f0be968600f0aeb0cfc323349dd91a64e85619f2063e65a1d",
//                "/Users/user/Documents/fidoMDS3/371d319829f0d9c3fbac22cb3972233f0e8c40d442baa8901c26e7ff75aafe71",
//                "/Users/user/Documents/fidoMDS3/b69ced87cf464443c0bff40f3eeb431d5f2e6ea3b343079d20af7eab4ce6eee5",
//                "/Users/user/Documents/fidoMDS3/dd898588fd43034eca9e4ea7038c14984af1e0d7a0618a07919fab146a934161",
//                "/Users/user/Documents/fidoMDS3/fe8dfd8670a5b4c8c736c46f3bc5ab33954bc2b878c30e94a987d453b26dc6d3"
//                ).map(filePath -> {
//            try {
//                Path path = Paths.get(filePath);
//                return new LocalFileMetadataBLOBProvider(objectConverter, path);
//            } catch (RuntimeException e) {
//                return null;
//            }
//        }).filter(Objects::nonNull).toArray(MetadataBLOBProvider[]::new);
//        /////////////////////////////////////////////////////

        MetadataBLOBBasedTrustAnchorRepository metadataBLOBBasedTrustAnchorRepository = new MetadataBLOBBasedTrustAnchorRepository(fidoMDS3MetdataBLOBProviders);

        // Load metadata statements from conformance tool.
        MetadataStatementsBasedTrustAnchorRepository metadataStatementsBasedTrustAnchorRepository = null;
        try {
            Path[] metadataPaths = Files.list(Paths.get("/Users/user/Documents/fidoMDS3/toolmetadata/metadataStatements")).toArray(Path[]::new);

            LocalFilesMetadataStatementsProvider localFilesMetadataStatementsProvider = new LocalFilesMetadataStatementsProvider(objectConverter, metadataPaths);
            metadataStatementsBasedTrustAnchorRepository = new MetadataStatementsBasedTrustAnchorRepository(
                    localFilesMetadataStatementsProvider
            );
        } catch (IOException e) {
            //
        }
        /////////////////////////////////////////////////////

        TrustAnchorRepository trustAnchorRepository;
        if (metadataStatementsBasedTrustAnchorRepository == null) {
            trustAnchorRepository = metadataBLOBBasedTrustAnchorRepository;
        } else {
            trustAnchorRepository = new AggregatingTrustAnchorRepository(
                    metadataBLOBBasedTrustAnchorRepository,
                    metadataStatementsBasedTrustAnchorRepository
            );
        }

        defaultCertPathTrustworthinessValidator = new DefaultCertPathTrustworthinessValidator(
                trustAnchorRepository
        );
        defaultCertPathTrustworthinessValidator.setFullChainProhibited(true);
    }

    private X509Certificate getMDS3RootCertificate() throws CertificateException, FileNotFoundException {
//        byte[] bytes = Base64Util.decode(
//                "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ" +
//                        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
//                        "IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
//                        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
//                        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
//                        "dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
//                        "BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL" +
//                        "TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T" +
//                        "EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
//                        "BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW" +
//                        "gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0" +
//                        "xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg" +
//                        "X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc="
//        );
//        return CertificateUtil.generateX509Certificate(bytes);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        FileInputStream fileInputStream = new FileInputStream("/Users/user/Documents/fidoMDS3/MDS3ROOT.crt");
        return (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
    }

    public DefaultCertPathTrustworthinessValidator getDefaultCertPathTrustworthinessValidator() {
        return defaultCertPathTrustworthinessValidator;
    }
}
