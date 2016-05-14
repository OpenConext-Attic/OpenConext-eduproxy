package eduproxy.web;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import eduproxy.AbstractIntegrationTest;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.util.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.*;
import java.util.Base64;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SingleSignOnControllerTest extends AbstractIntegrationTest {

  @Test
  public void testRegistrationProcess() throws Exception {
    String destination = "http://localhost:" + port + "/saml/idp";

    String url = samlRequestUtils.redirectUrl(entityId, destination, Optional.empty());
    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

    String saml = decodeSaml(response);

    assertTrue(saml.contains("AssertionConsumerServiceURL=\"http://localhost:8080/saml/SSO\""));
    assertTrue(saml.contains("Destination=\"https://engine.test.surfconext.nl/authentication/idp/single-sign-on\""));

    HttpHeaders httpHeaders = buildCookieHeaders(response);

    // now mimic a response from EB with a valid AuthnResponse with the cookie header

    String secondUrl = samlRequestUtils.redirectUrl(entityId, destination, Optional.empty());
    response = restTemplate.exchange(secondUrl, HttpMethod.GET, new HttpEntity<>(httpHeaders), String.class);

    String html = response.getBody();

    //this is response to the SP as we already have authenticated and we send the cookie
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
