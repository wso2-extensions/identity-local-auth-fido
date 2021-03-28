package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.DefaultApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.DefaultApiServiceImpl;

public class DefaultApiServiceFactory {

   private final static DefaultApiService service = new DefaultApiServiceImpl();

   public static DefaultApiService getDefaultApi()
   {
      return service;
   }
}
