package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.CredentialIdApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.CredentialIdApiServiceImpl;

public class CredentialIdApiServiceFactory {

   private final static CredentialIdApiService service = new CredentialIdApiServiceImpl();

   public static CredentialIdApiService getCredentialIdApi()
   {
      return service;
   }
}
