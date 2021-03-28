package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.StartUsernamelessRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.StartUsernamelessRegistrationApiServiceImpl;

public class StartUsernamelessRegistrationApiServiceFactory {

   private final static StartUsernamelessRegistrationApiService service = new StartUsernamelessRegistrationApiServiceImpl();

   public static StartUsernamelessRegistrationApiService getStartUsernamelessRegistrationApi()
   {
      return service;
   }
}
