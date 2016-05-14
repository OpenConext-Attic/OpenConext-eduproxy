package eduproxy.saml;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class IdentityProviderAuthnFilter extends OncePerRequestFilter {

  private final SAMLMessageHandler samlMessageHandler;

  public IdentityProviderAuthnFilter(SAMLMessageHandler samlMessageHandler) {
    this.samlMessageHandler = samlMessageHandler;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    if (authenticationNotRequired()) {
      sendAuthResponse(response);
    }
    /**
     * The SAMLRequest parameters are urlEncoded and the extraction expects unencoded parameters
     */
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(new ParameterDecodingHttpServletRequestWrapper(request));

    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    ProxySAMLAuthenticationToken token = new ProxySAMLAuthenticationToken(authnRequest, messageContext.getRelayState(), request.getRemoteAddr());
    SecurityContextHolder.getContext().setAuthentication(token);

    //redirect to login page - or trigger the sending of AuthRequest
    request.getRequestDispatcher("/saml/login").forward(request, response);
  }

  private void sendAuthResponse(HttpServletResponse response) {
    ProxySAMLAuthenticationToken token = (ProxySAMLAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
    try {
      samlMessageHandler.sendAuthnResponse(token, response);
    } catch (MarshallingException | SignatureException | MessageEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  private boolean authenticationNotRequired() {
    Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
    return existingAuth != null && existingAuth instanceof ProxySAMLAuthenticationToken && existingAuth.isAuthenticated();
  }

}
