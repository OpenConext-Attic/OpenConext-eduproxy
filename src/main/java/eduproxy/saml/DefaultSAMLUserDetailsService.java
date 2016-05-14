package eduproxy.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

public class DefaultSAMLUserDetailsService implements SAMLUserDetailsService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultSAMLUserDetailsService.class);

  @Override
  public SAMLCredential loadUserBySAML(SAMLCredential credential) {
    LOG.debug("loadUserBySAML {}", credential);
    return credential;
  }

}
