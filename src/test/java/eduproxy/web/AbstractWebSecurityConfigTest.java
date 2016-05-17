package eduproxy.web;


import eduproxy.AbstractIntegrationTest;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static org.junit.Assert.*;

public class AbstractWebSecurityConfigTest extends AbstractIntegrationTest {

  protected String entityId ="https://www.upsu.com/shibboleth";

  protected String acsLocation = "https://www.upsu.com/Shibboleth.sso/SAML/Artifact";

  protected String getSAMLResponseForError(ResponseEntity<String> response) {
    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());

    Matcher matcher = Pattern.compile("name=\"SAMLResponse\" value=\"(.*?)\"").matcher(response.getBody());
    assertTrue(matcher.find());

    return new String(Base64.getDecoder().decode(matcher.group(1)));
  }

  protected void assertAuthResponse(ResponseEntity<String> response) {
    String html;
    assertEquals(200, response.getStatusCode().value());

    html = response.getBody();

    assertTrue(html.contains("<input type=\"hidden\" name=\"SAMLResponse\""));
    assertTrue(html.contains("<body onload=\"document.forms[0].submit()\">"));

    Matcher matcher = Pattern.compile("name=\"SAMLResponse\" value=\"(.*?)\"").matcher(html);
    assertTrue(matcher.find());

    String samlResponseBase64Encoded = matcher.group(1);
    String samlResponse = new String(Base64.getDecoder().decode(samlResponseBase64Encoded));

    assertTrue(samlResponse.contains("Destination=\""+ acsLocation +"\""));
  }

  protected String decodeSaml(ResponseEntity<String> response) throws URISyntaxException, IOException {
    String location = response.getHeaders().getLocation().toString();

    Map<String, String> queryParameters = queryParameters(location);
    byte[] decodedBytes = Base64.getDecoder().decode(queryParameters.get("SAMLRequest"));

    return IOUtils.toString(new InflaterInputStream(new ByteArrayInputStream(decodedBytes), new Inflater(true)));
  }


}
