package eduproxy.saml;

import eduproxy.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;

import static org.junit.Assert.*;

public class DefaultMetadataDisplayFilterTest extends AbstractIntegrationTest{

  @Value("${am.entity_id}")
  private String amEntityId;

  @Test
  public void testProcessMetadataDisplay() throws Exception {
    String metadata = restTemplate.getForObject("http://localhost:" + port + "/saml/metadata", String.class);
    assertTrue(metadata.contains(amEntityId));
  }
}
