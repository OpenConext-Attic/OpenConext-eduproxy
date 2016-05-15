package eduproxy.saml;

import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ProxyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private static final Logger LOG = LoggerFactory.getLogger(ProxyAuthenticationSuccessHandler.class);

  private final SAMLMessageHandler samlMessageHandler;

  public ProxyAuthenticationSuccessHandler(SAMLMessageHandler samlMessageHandler) {
    this.samlMessageHandler = samlMessageHandler;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    SAMLPrincipal principal = (SAMLPrincipal) authentication.getPrincipal();
    LOG.debug("Sending response for successful authentication {}", authentication);

    try {
      samlMessageHandler.sendAuthnResponse(principal, response);
    } catch (MarshallingException | SignatureException | MessageEncodingException e) {
      throw new RuntimeException(e);
    }
  }

}
