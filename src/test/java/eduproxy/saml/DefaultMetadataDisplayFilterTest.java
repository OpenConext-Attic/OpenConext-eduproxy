package eduproxy.saml;

import eduproxy.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;

import static org.junit.Assert.*;

public class DefaultMetadataDisplayFilterTest extends AbstractIntegrationTest{

  @Test
  public void testProcessMetadataDisplay() throws Exception {
    String metadata = restTemplate.getForObject("http://localhost:" + port + "/sp/metadata", String.class);
    assertTrue(metadata.contains("entityID=\"https://eduproxy.localhost.surfconext.nl\""));
  }
}
