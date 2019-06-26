package org.wso2.carbon.identity.application.authenticator.fido2.cache;

import org.wso2.carbon.identity.application.common.cache.CacheKey;

public class FIDO2CacheKey extends CacheKey {

    private static final long serialVersionUID = -2846349295093760488L;
    //todo:variable name userAttributesId should be change later because userAttributesId = authorizationCode
    private String requestId;

    public FIDO2CacheKey(String requestId) {
        this.requestId = requestId;
    }

    public String getRequestId() {
        return requestId;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FIDO2CacheKey)) {
            return false;
        }
        return this.requestId.equals(((FIDO2CacheKey) o).getRequestId());
    }

    @Override
    public int hashCode() {
        return requestId.hashCode();
    }
}
