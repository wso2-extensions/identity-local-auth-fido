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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.yubico.internal.util.WebAuthnCodecs;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authenticator.fido2.dto.FIDOUser;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * FIDOUtil class for FIDO authentication component.
 */
public class FIDOUtil {

    private static Log log = LogFactory.getLog(FIDOUtil.class);

    private static final ObjectMapper jsonMapper = WebAuthnCodecs.json();
    private static final JsonNodeFactory jsonFactory = JsonNodeFactory.instance;

    private FIDOUtil() {
    }

	public static String getOrigin(HttpServletRequest request) {

		return request.getScheme() + "://" + request.getServerName() + ":" +
		       request.getServerPort();
	}

    public static String getDomainName(String username) {
        int index = username.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        if (index < 0) {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }
        return username.substring(0, index);
    }

    public static String getUsernameWithoutDomain(String username) {
        int index = username.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        if (index < 0) {
            return username;
        }
        return username.substring(index + 1, username.length());
    }

    public static FIDOUser getUser() {
        String loggedInUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String loggedInDomain = FIDOUtil.getDomainName(loggedInUser);
        String domainAwareUser = FIDOUtil.getUsernameWithoutDomain(loggedInUser);
        String loggedInTenant = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        FIDOUser user = new FIDOUser(domainAwareUser, loggedInTenant, loggedInDomain);
        return user;
    }

    public static Response finishResponse(Either<List<String>, ?> result, String jsonFailMessage, String methodName,
                                          String responseJson) {

        if (result.isRight()) {
            try {
                return Response.ok(
                        writeJson(result.right().get())
                ).build();
            } catch (JsonProcessingException e) {
                log.error(MessageFormat.format("Failed to encode response as JSON: {0}", result.right().get()),
                        e);
                return messagesJson(Response.ok(), jsonFailMessage);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(MessageFormat.format("fail {0} responseJson: {1}", methodName, responseJson));
            }
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), result.left().get());
        }
    }

    public static Response jsonFail() {

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("{\"messages\":[\"Failed to encode response as JSON\"]}").build();
    }

    public static Response messagesJson(Response.ResponseBuilder response, String message) {

        return messagesJson(response, Arrays.asList(message));
    }

    public static Response messagesJson(Response.ResponseBuilder response, List<String> messages) {

        if (log.isDebugEnabled()) {
            log.debug(MessageFormat.format("Encoding messages as JSON: {0}", messages));
        }
        try {
            return response.entity(writeJson(jsonFactory.objectNode().set("messages", jsonFactory.arrayNode()
                    .addAll(messages.stream().map(jsonFactory::textNode).collect(Collectors.toList())))))
                    .build();
        } catch (JsonProcessingException e) {
            log.error(MessageFormat.format("Failed to encode messages as JSON: {0}", messages), e);
            return jsonFail();
        }
    }

    public static String writeJson(Object o) throws JsonProcessingException {

        return jsonMapper.writeValueAsString(o);
    }
}
