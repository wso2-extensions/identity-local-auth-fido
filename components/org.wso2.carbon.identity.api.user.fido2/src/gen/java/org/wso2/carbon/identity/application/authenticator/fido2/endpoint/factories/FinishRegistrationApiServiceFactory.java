package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.factories;

import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.FinishRegistrationApiService;
import org.wso2.carbon.identity.application.authenticator.fido2.endpoint.impl.FinishRegistrationApiServiceImpl;

public class FinishRegistrationApiServiceFactory {

   private final static FinishRegistrationApiService service = new FinishRegistrationApiServiceImpl();

   public static FinishRegistrationApiService getFinishRegistrationApi()
   {
      return service;
   }
}
