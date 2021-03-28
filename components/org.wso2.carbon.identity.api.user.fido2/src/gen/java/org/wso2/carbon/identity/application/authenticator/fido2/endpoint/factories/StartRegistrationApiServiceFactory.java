package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.StartRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.StartRegistrationApiServiceImpl;

public class StartRegistrationApiServiceFactory {

   private final static StartRegistrationApiService service = new StartRegistrationApiServiceImpl();

   public static StartRegistrationApiService getStartRegistrationApi()
   {
      return service;
   }
}
