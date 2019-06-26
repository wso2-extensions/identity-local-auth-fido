package io.swagger.api;

import io.swagger.model.Error;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MediaType;
import org.apache.cxf.jaxrs.ext.multipart.*;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ApiResponse;
import io.swagger.jaxrs.PATCH;
import org.wso2.carbon.identity.application.authenticator.fido2.exception.FIDO2AuthenticatorException;

import javax.validation.constraints.*;
import javax.validation.Valid;

/**
 * WSO2 Identity Server FIDO 2 Rest API 
 *
 * <p>This document specifies a **FIDO 2 RESTfulAPI** for WSO2 **Identity Server** .  It is written with [swagger 2](http://swagger.io/). 
 *
 */
@Path("/")
@Api(value = "/", description = "")
public interface FidoApi  {

    /**
     * Deregister devices by username and credentialId 
     *
     * This API is used to deregister devices by username and credentialId. 
     *
     */
    @DELETE
    @Path("/me/webauthn/{credentialId}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Deregister devices by username and credentialId ", tags={ "FIDO",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "OK"),
        @ApiResponse(code = 400, message = "Bad Request", response = Error.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Error.class),
        @ApiResponse(code = 404, message = "Not Found", response = Error.class),
        @ApiResponse(code = 500, message = "Server Error", response = Error.class) })
    public void meWebauthnCredentialIdDelete(@PathParam("credentialId") String credentialId);

    /**
     * complete device registration 
     *
     * This API is used to complete the device registration 
     *
     */
    @POST
    @Path("/me/webauthn/finish-registration")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "complete device registration ", tags={ "FIDO",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Successful response", response = String.class),
        @ApiResponse(code = 400, message = "Bad Request", response = Error.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Error.class),
        @ApiResponse(code = 409, message = "Conflict", response = Error.class),
        @ApiResponse(code = 500, message = "Server Error", response = Error.class) })
    public String meWebauthnFinishRegistrationPost(@Valid String response);

    /**
     * Start FIDO registration 
     *
     * This API is used to start fido device registration process. 
     *
     */
    @POST
    @Path("/me/webauthn/start-registration")
    @Consumes({ "application/x-www-form-urlencoded" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Start FIDO registration ", tags={ "FIDO",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Successful response", response = String.class),
        @ApiResponse(code = 400, message = "Bad Request", response = Error.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Error.class),
        @ApiResponse(code = 409, message = "Conflict", response = Error.class),
        @ApiResponse(code = 500, message = "Server Error", response = Error.class) })
    public String meWebauthnStartRegistrationPost(@Multipart(value = "appId")  String appId) throws FIDO2AuthenticatorException;

    /**
     * Device Metadata 
     *
     * This API is used to get fido metadata by username. 
     *
     */
    @GET
    @Path("/metadata")
    @Consumes({ "application/x-www-form-urlencoded" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Device Metadata ", tags={ "FIDO" })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Successful response", response = String.class),
        @ApiResponse(code = 400, message = "Bad Request", response = Error.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Error.class),
        @ApiResponse(code = 409, message = "Conflict", response = Error.class),
        @ApiResponse(code = 500, message = "Server Error", response = Error.class) })
    public String metadataGet(@QueryParam("username") @NotNull String username);
}

