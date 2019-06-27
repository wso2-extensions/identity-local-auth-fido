package io.swagger.api.impl;

import io.swagger.api.*;
import io.swagger.model.Error;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import org.apache.cxf.jaxrs.model.wadl.Description;
import org.apache.cxf.jaxrs.model.wadl.DocTarget;

import org.apache.cxf.jaxrs.ext.multipart.*;

import io.swagger.annotations.Api;

/**
 * WSO2 Identity Server FIDO 2 Rest API 
 *
 * <p>This document specifies a **FIDO 2 RESTfulAPI** for WSO2 **Identity Server** .  It is written with [swagger 2](http://swagger.io/). 
 *
 */
public class FidoApiServiceImpl implements FidoApi {
    /**
     * Deregister devices by username and credentialId 
     *
     * This API is used to deregister devices by username and credentialId. 
     *
     */
    public void meWebauthnCredentialIdDelete(String credentialId) {
        // TODO: Implement...
        
        
    }
    
    /**
     * complete device registration 
     *
     * This API is used to complete the device registration 
     *
     */
    public String meWebauthnFinishRegistrationPost(String response) {
        // TODO: Implement...
        
        return null;
    }
    
    /**
     * Device Metadata 
     *
     * This API is used to get fido metadata by username. 
     *
     */
    public String meWebauthnGet(String username) {
        // TODO: Implement...
        
        return null;
    }
    
    /**
     * Start FIDO registration 
     *
     * This API is used to start fido device registration process. 
     *
     */
    public String meWebauthnStartRegistrationPost(String appId) {
        // TODO: Implement...
        
        return null;
    }
    
}

