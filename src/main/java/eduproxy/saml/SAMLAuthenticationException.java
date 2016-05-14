package eduproxy.saml;

import org.opensaml.common.binding.BasicSAMLMessageContext;

public class SAMLAuthenticationException extends RuntimeException {

  private final BasicSAMLMessageContext messageContext;

  public SAMLAuthenticationException(String message, Exception exception, BasicSAMLMessageContext messageContext) {
    super(message, exception);
    this.messageContext = messageContext;
  }

  public BasicSAMLMessageContext getMessageContext() {
    return messageContext;
  }
}
