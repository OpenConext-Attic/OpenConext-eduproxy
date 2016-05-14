package eduproxy.saml;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLAuthenticationProvider;

public class ProxySAMLAuthenticationProvider extends SAMLAuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    return super.authenticate(authentication);
  }
}
