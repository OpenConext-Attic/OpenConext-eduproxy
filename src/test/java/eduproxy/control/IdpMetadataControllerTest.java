package eduproxy.control;

import eduproxy.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.Assert.*;

public class IdpMetadataControllerTest extends AbstractIntegrationTest {

  @Test
  public void testMetadata() throws Exception {
    ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/idp/metadata", String.class);

    assertEquals(200, response.getStatusCode().value());
    String xml = response.getBody();

    assertTrue(xml.contains("<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));
    assertTrue(xml.contains("entityID=\"https://eduproxy.localhost.surfconext.nl\""));

  }
}
