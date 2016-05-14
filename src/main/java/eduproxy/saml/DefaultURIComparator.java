package eduproxy.saml;

import org.opensaml.common.binding.decoding.URIComparator;

import java.net.URI;
import java.net.URISyntaxException;

public class DefaultURIComparator implements URIComparator {

  @Override
  public boolean compare(String uri1, String uri2) {
    try {
      return uri1 == null ? uri2 == null : uri2 == null ? uri1 == null : compareIgnoreSchema(uri1, uri2);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private boolean compareIgnoreSchema(String s1, String s2) throws URISyntaxException {
    URI uri1 = new URI(s1);
    URI uri2 = new URI(s1);
    return uri1.getSchemeSpecificPart().equalsIgnoreCase(uri2.getSchemeSpecificPart());

  }
}
