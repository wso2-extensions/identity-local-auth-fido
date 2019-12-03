package org.wso2.carbon.identity.application.authenticator.fido2.endpoint;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.*;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.CredentialIdApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories.CredentialIdApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/{credentialId}")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/{credentialId}", description = "the {credentialId} API")
public class CredentialIdApi  {

   private final CredentialIdApiService delegate = CredentialIdApiServiceFactory.getCredentialIdApi();

    @DELETE
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Deregister devices by username and credentialId.\n", notes = "This API is used to deregister devices by username and credentialId.\n\n<b>Permission required:</b>\n * /permission/admin/login\n", response = void.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 204, message = "No Content"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 403, message = "Resource Forbidden"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response credentialIdDelete(@ApiParam(value = "credentialId",required=true ) @PathParam("credentialId")  String credentialId)
    {
    return delegate.credentialIdDelete(credentialId);
    }
}

