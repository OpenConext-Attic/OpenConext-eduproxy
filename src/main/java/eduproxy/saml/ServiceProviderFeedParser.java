package eduproxy.saml;

import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;

public class ServiceProviderFeedParser {

  private final Resource resource;

  public ServiceProviderFeedParser(Resource resource) {
    this.resource = resource;
  }

  public Map<String, String> parse() throws IOException, XMLStreamException {
    //despite it's name, the XMLInputFactoryImpl is not thread safe
    XMLInputFactory factory = XMLInputFactory.newInstance();

    XMLStreamReader reader = factory.createXMLStreamReader(resource.getInputStream());

    Map<String, String> serviceProviders = new HashMap<>();
    String entityId = null;
    boolean isServiceProvider = false, isSigning = false;
    while (reader.hasNext()) {
      switch (reader.next()) {
        case START_ELEMENT:
          switch (reader.getLocalName()) {
            case "EntityDescriptor":
              entityId = reader.getAttributeValue(null, "entityID");
              isServiceProvider = false;
              break;
            case "SPSSODescriptor":
              isServiceProvider = true;
              break;
            case "KeyDescriptor":
              isSigning = "signing".equals(reader.getAttributeValue(null, "use"));
              break;
            case "X509Certificate": {
              if (isServiceProvider && isSigning) {
                serviceProviders.put(entityId, reader.getElementText().replaceAll("\\s",""));
              }
            }
          }
      }
    }
    return serviceProviders;
  }

}
