package eduproxy.saml;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.springframework.security.saml.SAMLConstants.PEER_ENTITY_ID;

public class DefaultSAMLEntryPointTest {

  private DefaultSAMLEntryPoint subject = new DefaultSAMLEntryPoint("central-idp-entity-id","surfconext-entity-id") {
    @Override
    protected void doCommence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
      //nope
    }
  };

  @Before
  public void setUp() throws Exception {
    SecurityContextHolder.getContext().setAuthentication(null);
  }



  @Test
  public void testCommenceToCentralIdp() throws Exception {
    doCommence("central-idp-entity-id");
  }

  private void doCommence(String expectedEntityId) throws IOException, ServletException {
    MockHttpServletRequest request = new MockHttpServletRequest();

    subject.commence(request,new MockHttpServletResponse(), null);

    assertEquals(expectedEntityId, request.getAttribute(PEER_ENTITY_ID));
  }
}
