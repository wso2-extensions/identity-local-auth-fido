package org.wso2.carbon.identity.application.authenticator.fido2.endpoint.dto;

import io.swagger.annotations.ApiModel;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;



/**
 * A JSONPatch as defined by RFC 6902. Patch operation is supported only for root level attributes of an Identity Provider.
 **/


@ApiModel(description = "A JSONPatch as defined by RFC 6902. Patch operation is supported only for root level attributes of an Identity Provider.")
public class PatchDTO  {
  
  
  public enum OperationEnum {
     ADD,  REMOVE,  REPLACE, 
  };
  @NotNull
  private OperationEnum operation = null;
  
  @NotNull
  private String path = null;
  
  
  private String value = null;

  
  /**
   * The operation to be performed
   **/
  @ApiModelProperty(required = true, value = "The operation to be performed")
  @JsonProperty("operation")
  public OperationEnum getOperation() {
    return operation;
  }
  public void setOperation(OperationEnum operation) {
    this.operation = operation;
  }

  
  /**
   * A JSON-Pointer
   **/
  @ApiModelProperty(required = true, value = "A JSON-Pointer")
  @JsonProperty("path")
  public String getPath() {
    return path;
  }
  public void setPath(String path) {
    this.path = path;
  }

  
  /**
   * The value to be used within the operations
   **/
  @ApiModelProperty(value = "The value to be used within the operations")
  @JsonProperty("value")
  public String getValue() {
    return value;
  }
  public void setValue(String value) {
    this.value = value;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class PatchDTO {\n");
    
    sb.append("  operation: ").append(operation).append("\n");
    sb.append("  path: ").append(path).append("\n");
    sb.append("  value: ").append(value).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
