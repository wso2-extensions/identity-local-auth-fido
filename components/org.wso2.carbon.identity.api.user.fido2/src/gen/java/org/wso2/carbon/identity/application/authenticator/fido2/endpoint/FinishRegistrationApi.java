package org.wso2.carbon.identity.application.authenticator.fido2.endpoint;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.*;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.FinishRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories.FinishRegistrationApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/finish-registration")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/finish-registration", description = "the finish-registration API")
public class FinishRegistrationApi  {

   private final FinishRegistrationApiService delegate = FinishRegistrationApiServiceFactory.getFinishRegistrationApi();

    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Complete FIDO2 device registration.\n", notes = "This API is used to complete FIDO2 device registration flow.\n\n<b>Permission required:</b>\n * /permission/admin/login\n", response = Object.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 201, message = "Device registered successfully."),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 403, message = "Resource Forbidden"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response finishRegistrationPost(@ApiParam(value = "Response from the client." ,required=true ) String challengeResponse)
    {
    return delegate.finishRegistrationPost(challengeResponse);
    }
}

