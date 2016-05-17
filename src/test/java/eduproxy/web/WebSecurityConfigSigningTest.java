package eduproxy.web;


import eduproxy.AbstractIntegrationTest;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.WebIntegrationTest;
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

@WebIntegrationTest(value = {"server.port=0", "spring.profiles.active=dev", "serviceproviders.require_signing=true"})
public class WebSecurityConfigSigningTest extends AbstractWebSecurityConfigTest {

  @Test
  public void testProxyWithoutSignature() throws Exception {
    String destination = "http://localhost:" + port + "/saml/idp";

    String url = samlRequestUtils.redirectUrl(entityId, destination, acsLocation, Optional.empty(), false);
    String withoutSignature = url.replaceFirst("&Signature[^&]+", "");

    ResponseEntity<String> response = restTemplate.getForEntity(withoutSignature, String.class);

    String saml = getSAMLResponseForError(response);

    assertTrue(saml.contains("Signature required, but not present in authnRequest or request for " + entityId));
    assertFalse(saml.contains("Subject"));
  }

}
