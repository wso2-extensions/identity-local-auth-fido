package org.wso2.carbon.identity.application.authenticator.fido2.endpoint;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.*;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.DefaultApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories.DefaultApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto.ErrorDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/", description = "the default API")
public class DefaultApi  {

   private final DefaultApiService delegate = DefaultApiServiceFactory.getDefaultApi();

    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Device Metadata\n", notes = "This API is used to get fido metadata by username.\n\n<b>Permission required:</b>\n * /permission/admin/login\n", response = Object.class, responseContainer = "List")
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "All available fido metadata for a user."),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 403, message = "Resource Forbidden"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response rootGet()
    {
    return delegate.rootGet();
    }
}

