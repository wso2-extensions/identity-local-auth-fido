package org.wso2.carbon.identity.application.authenticator.fido2.endpoint;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.*;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.StartRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories.StartRegistrationApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/start-registration")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/start-registration", description = "the start-registration API")
public class StartRegistrationApi  {

   private final StartRegistrationApiService delegate = StartRegistrationApiServiceFactory.getStartRegistrationApi();

    @POST
    
    @Consumes({ "application/x-www-form-urlencoded" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Trigger FIDO2 device registration.\n", notes = "This API is used to trigger FIDO2 device registration flow.\n\n <b>Permission required:</b>\n * /permission/admin/login\n", response = Object.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 201, message = "Successful response"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 403, message = "Resource Forbidden"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response startRegistrationPost(@ApiParam(value = "Represents the host name of FIDO request initiator.", required=true )@Multipart(value = "appId")  String appId)
    {
    return delegate.startRegistrationPost(appId);
    }
}

