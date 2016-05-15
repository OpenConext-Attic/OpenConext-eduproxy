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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WebSecurityConfigTest extends AbstractIntegrationTest {

  @Test
  public void testProxy() throws Exception {
    String destination = "http://localhost:" + port + "/saml/idp";

    String url = samlRequestUtils.redirectUrl(entityId, destination, Optional.empty());

    //This mimics the AuthRequest from a SP to the eduProxy IDP endpoint
    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

    String saml = decodeSaml(response);

    assertTrue(saml.contains("AssertionConsumerServiceURL=\"http://localhost:8080/saml/SSO\""));
    assertTrue(saml.contains("Destination=\"https://engine.test.surfconext.nl/authentication/idp/single-sign-on\""));

    Matcher matcher = Pattern.compile("ID=\"(.*?)\"").matcher(saml);
    assertTrue(matcher.find());

    //We need the ID of the original request to mimic the real IdP authnResponse
    String inResponseTo = matcher.group(1);

    ZonedDateTime date = ZonedDateTime.now();
    String now = date.format(DateTimeFormatter.ISO_INSTANT);
    String samlResponse = IOUtils.toString(new ClassPathResource("saml/eb.authnResponse.saml.xml").getInputStream());

    //Make sure the all the validations pass. We don't sign as this is in dev modus not necessary
    samlResponse = samlResponse.replaceAll("@@IssueInstant@@", now);
    samlResponse = samlResponse.replaceAll("@@NotBefore@@", now);
    samlResponse = samlResponse.replaceAll("@@NotOnOrAfter@@", date.plus(5, ChronoUnit.MINUTES).format(DateTimeFormatter.ISO_INSTANT));
    samlResponse = samlResponse.replaceAll("@@InResponseTo@@", inResponseTo);

    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("SAMLResponse", Base64.getEncoder().encodeToString(samlResponse.getBytes()));

    HttpHeaders httpHeaders = buildCookieHeaders(response);

    // now mimic a response from the real IdP with a valid AuthnResponse and the correct cookie header
    HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, httpHeaders);
    response = restTemplate.exchange("http://localhost:" + port + "/saml/SSO", HttpMethod.POST, httpEntity, String.class);

    assertAuthResponse(response);

    // now verify that we hit the cached principal
    String secondUrl = samlRequestUtils.redirectUrl(entityId, destination, Optional.empty());

    response = restTemplate.exchange(secondUrl, HttpMethod.GET, new HttpEntity<>(httpHeaders), String.class);

    assertAuthResponse(response);

    //we can now call index
    response = restTemplate.exchange("http://localhost:" + port + "/user", HttpMethod.GET, new HttpEntity<>(httpHeaders), String.class);
    String html = response.getBody();

    assertEquals(200 , response.getStatusCode().value());
    assertTrue(html.contains("nameID"));
    assertTrue(html.contains("urn:collab:person:example.com:admin"));
    assertTrue(html.contains("j.doe@example.com"));
  }

  @Test
  public void testSAMLAuthenticationException() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    String url = samlRequestUtils.redirectUrl(entityId, "http://localhost:" + port + "/", Optional.empty());
    String mangledUrl = url.replaceFirst("&Signature[^&]+", "&Signature=bogus");
    ResponseEntity<String> response = restTemplate.getForEntity(mangledUrl, String.class);

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());

    Matcher matcher = Pattern.compile("name=\"SAMLResponse\" value=\"(.*?)\"").matcher(response.getBody());
    assertTrue(matcher.find());

    String saml = new String(Base64.getDecoder().decode(matcher.group(1)));

    assertTrue(saml.contains("Exception during validation of AuthnRequest"));
    assertFalse(saml.contains("Subject"));
  }


  private void assertAuthResponse(ResponseEntity<String> response) {
    String html;
    assertEquals(200, response.getStatusCode().value());

    html = response.getBody();

    assertTrue(html.contains("<input type=\"hidden\" name=\"SAMLResponse\""));
    assertTrue(html.contains("<body onload=\"document.forms[0].submit()\">"));
  }

  private String decodeSaml(ResponseEntity<String> response) throws URISyntaxException, IOException {
    String location = response.getHeaders().getLocation().toString();

    Map<String, String> queryParameters = queryParameters(location);
    byte[] decodedBytes = Base64.getDecoder().decode(queryParameters.get("SAMLRequest"));

    return IOUtils.toString(new InflaterInputStream(new ByteArrayInputStream(decodedBytes), new Inflater(true)));
  }


}
