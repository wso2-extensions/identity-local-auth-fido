/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.internal;

import lombok.SneakyThrows;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.fido2.util.FIDOUtil;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Scheduler service to run FIDO2 metadata related tasks.
 */
public class MetadataSchedulerService {

    private static final int NO_OF_THREADS = 1;
    private static final Log log = LogFactory.getLog(MetadataSchedulerService.class);
    private final ScheduledExecutorService scheduler;
    private final long delay;

    public MetadataSchedulerService(long delay) {

        this.delay = delay;
        this.scheduler = Executors.newScheduledThreadPool(NO_OF_THREADS);
    }

    public void activateMetadataInitialization() {

        Runnable metadataInitializationTask = new MetadataInitializationTask();
        scheduler.schedule(metadataInitializationTask, delay, TimeUnit.MINUTES);
        log.info("FIDO2 Metadata Scheduler service is activated.");
    }

    private static final class MetadataInitializationTask implements Runnable {

        @SneakyThrows(FIDO2AuthenticatorServerException.class)
        @Override
        public void run() {

            log.debug("Start running the FIDO2 Metadata Initialization task.");
            if (FIDOUtil.isMetadataValidationsEnabled()) {
                if (FIDO2AuthenticatorServiceDataHolder.getInstance().getMetadataService() == null) {
                    log.debug("Setting a new MetadataService object as the FIDO Authenticator metadata service " +
                            "is null");
                    FIDO2AuthenticatorServiceDataHolder.getInstance().setMetadataService(new MetadataService());
                }

                FIDO2AuthenticatorServiceDataHolder.getInstance().getMetadataService()
                        .initializeDefaultCertPathTrustworthinessValidator();

                if (FIDO2AuthenticatorServiceDataHolder.getInstance().getMetadataService()
                        .getDefaultCertPathTrustworthinessValidator() == null) {
                    log.error("Error initializing default cert path trustworthiness validator");
                } else {
                    log.info("FIDO2 Metadata Initialization is successful.");
                }
            }
            log.debug("Stop running the FIDO2 Metadata Initialization task.");
        }
    }
}
