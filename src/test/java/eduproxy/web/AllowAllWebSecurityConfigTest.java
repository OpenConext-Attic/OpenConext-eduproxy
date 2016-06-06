package eduproxy.web;


import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


@WebIntegrationTest(value = {"server.port=0", "spring.profiles.active=dev", "serviceproviders.allow_unknown=true"})
public class AllowAllWebSecurityConfigTest extends AbstractWebSecurityConfigTest {

  @Test
  public void testInvalidEntityIDButAllowed() throws Exception {
    String url = samlRequestUtils.redirectUrl("http://bogus", "http://localhost:" + port + "/saml/idp", acsLocation, Optional.empty(), false);

    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
    String saml = decodeSaml(response);

    assertTrue(saml.contains("Destination=\"https://engine.test2.surfconext.nl/authentication/idp/single-sign-on\""));
  }

}
