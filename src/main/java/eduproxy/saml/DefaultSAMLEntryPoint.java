package eduproxy.saml;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.saml.SAMLConstants.*;

public class DefaultSAMLEntryPoint extends SAMLEntryPoint {

  private final String centralIdpEntityId;
  private final String surfConextEntityId;

  public DefaultSAMLEntryPoint(String centralIdpEntityId, String surfConextEntityId) {
    this.centralIdpEntityId = centralIdpEntityId;
    this.surfConextEntityId = surfConextEntityId;
  }

  /**
   * We commence to the central IdP when there is no logged in user yet, otherwise we commence to the SURFConext IdP
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
//    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    if (authentication != null && authentication.getPrincipal() instanceof User) {
//      request.setAttribute(PEER_ENTITY_ID, surfConextEntityId);
//    } else {
//      request.setAttribute(PEER_ENTITY_ID, centralIdpEntityId);
//    }
    doCommence(request, response, e);
  }

  // For testing purposes
  protected void doCommence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
    super.commence(request, response, e);
  }
}
