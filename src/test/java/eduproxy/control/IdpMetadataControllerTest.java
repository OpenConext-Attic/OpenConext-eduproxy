package eduproxy.control;

import eduproxy.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.ResponseEntity;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.chrono.ChronoZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalField;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

@WebIntegrationTest(value = {"server.port=0", "proxy.validity_duration_metadata_ms=1"})
public class IdpMetadataControllerTest extends AbstractIntegrationTest {

  @Test
  public void testMetadata() throws Exception {
    ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/idp/metadata", String.class);

    assertEquals(200, response.getStatusCode().value());
    String xml = response.getBody();

    assertTrue(xml.contains("<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));
    assertTrue(xml.contains("entityID=\"https://eduproxy.localhost.surfconext.nl\""));

    xml = restTemplate.getForEntity("http://localhost:" + port + "/idp/metadata", String.class).getBody();
    Matcher matcher = Pattern.compile("validUntil=\"(.*?)\"").matcher(xml);

    assertTrue(matcher.find());

    TemporalAccessor parse = DateTimeFormatter.ISO_INSTANT.parse(matcher.group(1));

    assertTrue(System.currentTimeMillis() > parse.getLong(ChronoField.INSTANT_SECONDS) * 1000);

  }
}
