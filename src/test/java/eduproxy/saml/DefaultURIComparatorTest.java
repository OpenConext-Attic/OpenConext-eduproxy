package eduproxy.saml;

import org.junit.Test;
import org.opensaml.common.binding.decoding.URIComparator;

import static org.junit.Assert.*;

public class DefaultURIComparatorTest {

  private URIComparator subject = new DefaultURIComparator();

  @Test
  public void testCompare() throws Exception {
    String https = "https://attribute-mapper.test.surfconext.nl/saml/SSO";
    String http = "http://attribute-mapper.test.surfconext.nl/saml/SSO";
    assertTrue(subject.compare(https, http));
  }

  @Test
  public void testNulls() throws Exception  {
    assertFalse(subject.compare(null, "http://local"));
    assertFalse(subject.compare("http://local", null));

    assertTrue(subject.compare(null, null));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testInvalidURI() {
    subject.compare("x!x::invalid", "http://local");
  }
}
