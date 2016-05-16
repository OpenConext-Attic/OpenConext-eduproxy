package eduproxy.saml;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ServiceProviderFeedParserTest {

  private ServiceProviderFeedParser parser = new ServiceProviderFeedParser(new ClassPathResource("saml/edugain.xml"));

  @Test
  public void testParse() throws Exception {
    Map<String, String> serviceProviders = parser.parse();
    assertEquals(337, serviceProviders.size());
  }




}
