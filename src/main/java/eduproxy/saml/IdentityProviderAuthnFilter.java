package eduproxy.saml;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class IdentityProviderAuthnFilter extends OncePerRequestFilter implements AuthenticationEntryPoint {

  private final SAMLMessageHandler samlMessageHandler;

  public IdentityProviderAuthnFilter(SAMLMessageHandler samlMessageHandler) {
    this.samlMessageHandler = samlMessageHandler;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    if (authenticationNotRequired()) {
      sendAuthResponse(response);
      return;
    }

    //The SAMLRequest parameters are urlEncoded and the extraction expects unencoded parameters
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(new ParameterDecodingHttpServletRequestWrapper(request));

    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    SAMLPrincipal principal = new SAMLPrincipal(authnRequest.getIssuer().getValue(), authnRequest.getID(),
      authnRequest.getAssertionConsumerServiceURL(), messageContext.getRelayState());

    SecurityContextHolder.getContext().setAuthentication(new SAMLAuthentication(principal));

    //forward to login page will trigger the sending of AuthRequest to the IdP
    request.getRequestDispatcher("/saml/login").forward(request, response);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    if (!SAMLUtil.processFilter("/saml/idp", request)) {
      chain.doFilter(request, response);
      return;
    }
    commence(request, response, null);
  }

  private void sendAuthResponse(HttpServletResponse response) {
    SAMLPrincipal principal = (SAMLPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    samlMessageHandler.sendAuthnResponse(principal, response);
  }

  private boolean authenticationNotRequired() {
    Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
    return existingAuth != null && existingAuth.getPrincipal() instanceof SAMLPrincipal && existingAuth.isAuthenticated();
  }

}
