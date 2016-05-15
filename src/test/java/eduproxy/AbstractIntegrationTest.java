package eduproxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebIntegrationTest(value = {"server.port=0", "spring.profiles.active=dev"})
public abstract class AbstractIntegrationTest {

  protected RestTemplate restTemplate = new TestRestTemplate();

  @Value("${local.server.port}")
  protected int port;

  @Value("${proxy.entity_id}")
  protected String entityId;

  @Autowired
  private CredentialResolver credentialResolver;

  protected SAMLRequestUtils samlRequestUtils;

  @Rule
  public WireMockRule bioMetricMock = new WireMockRule(9000);

  @BeforeClass
  public static void beforeClass() throws ConfigurationException {
    DefaultBootstrap.bootstrap();
  }

  @Before
  public void before() throws IOException {
    samlRequestUtils = new SAMLRequestUtils(credentialResolver);
  }

  protected HttpHeaders buildCookieHeaders(ResponseEntity<?> response) {
    List<String> cookies = response.getHeaders().get("Set-Cookie");
    assertEquals(1, cookies.size());

    //Something like JSESSIONID=j2qqhxkq9wfy1ngsqouvebxud;Path=/
    String sessionId = cookies.get(0);

    HttpHeaders requestHeaders = new HttpHeaders();
    requestHeaders.add("Cookie", sessionId.replaceAll(";.*", ""));
    return requestHeaders;
  }

  protected Map<String, String> queryParameters(String url) throws URISyntaxException {
    return asList(url.substring(url.indexOf("?") + 1).split("&")).stream()
      .map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> decode(s[1])));
  }

  private String decode(String encoded) {
    try {
      return URLDecoder.decode(encoded, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }


}
