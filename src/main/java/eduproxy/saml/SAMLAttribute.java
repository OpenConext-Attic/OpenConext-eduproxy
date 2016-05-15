package eduproxy.saml;

import java.util.Collections;
import java.util.List;

public class SAMLAttribute {

  private final String name;
  private final List<String> values;

  public SAMLAttribute(String name, List<String> values) {
    this.name = name;
    this.values = values;
  }

  public String getName() {
    return name;
  }

  public List<String> getValues() {
    return values;
  }

  @Override
  public String toString() {
    return "SAMLAttribute{" +
      "name='" + name + '\'' +
      ", values=" + values +
      '}';
  }
}
