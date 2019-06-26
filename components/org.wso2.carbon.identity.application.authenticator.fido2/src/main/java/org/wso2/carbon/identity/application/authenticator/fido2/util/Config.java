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

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class Config {

    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    private static final String DEFAULT_ORIGIN = "https://localhost:8443";
    private static final int DEFAULT_PORT = 8080;
    private static final RelyingPartyIdentity DEFAULT_RP_ID
        = RelyingPartyIdentity.builder().id("localhost").name("Yubico WebAuthn demo").build();

    private final Set<String> origins;
    private final int port;
    private final RelyingPartyIdentity rpIdentity;
    private final Optional<AppId> appId;

    private Config(Set<String> origins, int port, RelyingPartyIdentity rpIdentity, Optional<AppId> appId) {
        this.origins = CollectionUtil.immutableSet(origins);
        this.port = port;
        this.rpIdentity = rpIdentity;
        this.appId = appId;
    }

    private static Config instance;
    private static Config getInstance() {
        if (instance == null) {
            try {
                instance = new Config(computeOrigins(), computePort(), computeRpIdentity(), computeAppId());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            } catch (InvalidAppIdException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }

    public static Set<String> getOrigins() {
        return getInstance().origins;
    }

    public static int getPort() {
        return getInstance().port;
    }

    public static RelyingPartyIdentity getRpIdentity() {
        return getInstance().rpIdentity;
    }

    public static Optional<AppId> getAppId() {
        return getInstance().appId;
    }

    private static Set<String> computeOrigins() {
        final String origins = System.getenv("YUBICO_WEBAUTHN_ALLOWED_ORIGINS");

        logger.debug("YUBICO_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

        final Set<String> result;

        if (origins == null) {
            result = Collections.singleton(DEFAULT_ORIGIN);
        } else {
            result = new HashSet<>(Arrays.asList(origins.split(",")));
        }

        logger.info("Origins: {}", result);

        return result;
    }

    private static int computePort() {
        final String port = System.getenv("YUBICO_WEBAUTHN_PORT");

        if (port == null) {
            return DEFAULT_PORT;
        } else {
            return Integer.parseInt(port);
        }
    }

    private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException {
        final String name = System.getenv("YUBICO_WEBAUTHN_RP_NAME");
        final String id = System.getenv("YUBICO_WEBAUTHN_RP_ID");
        final String icon = System.getenv("YUBICO_WEBAUTHN_RP_ICON");

        logger.debug("RP name: {}", name);
        logger.debug("RP ID: {}", id);
        logger.debug("RP icon: {}", icon);

        RelyingPartyIdentity.RelyingPartyIdentityBuilder resultBuilder = DEFAULT_RP_ID.toBuilder();

        if (name == null) {
            logger.debug("RP name not given - using default.");
        } else {
            resultBuilder.name(name);
        }

        if (id == null) {
            logger.debug("RP ID not given - using default.");
        } else {
            resultBuilder.id(id);
        }

        if (icon == null) {
            logger.debug("RP icon not given - using none.");
        } else {
            try {
            resultBuilder.icon(Optional.of(new URL(icon)));
            } catch (MalformedURLException e) {
                logger.error("Invalid icon URL: {}", icon, e);
                throw e;
            }
        }

        final RelyingPartyIdentity result = resultBuilder.build();
        logger.info("RP identity: {}", result);
        return result;
    }

    private static Optional<AppId> computeAppId() throws InvalidAppIdException {
        final String appId = System.getenv("YUBICO_WEBAUTHN_U2F_APPID");
        logger.debug("YUBICO_WEBAUTHN_U2F_APPID: {}", appId);

        AppId result = appId == null
            ? new AppId("https://localhost:8443")
            : new AppId(appId);

        logger.debug("U2F AppId: {}", result.getId());
        return Optional.of(result);
    }

}
