package eduproxy.saml;

import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml.SAMLCredential;

public class ProxySAMLAuthenticationToken extends AbstractAuthenticationToken {

  private final AuthnRequest authnRequest;
  private final String relayState;
  private final String remoteAddr;
  private SAMLCredential samlCredential;

  public ProxySAMLAuthenticationToken(AuthnRequest authnRequest, String relayState, String remoteAddr) {
    super(AuthorityUtils.NO_AUTHORITIES);
    this.authnRequest = authnRequest;
    this.relayState = relayState;
    this.remoteAddr = remoteAddr;
  }

  @Override
  public Object getCredentials() {
    return "N/A";
  }

  @Override
  public Object getPrincipal() {
    return authnRequest.getID();
  }

  public SAMLCredential getSAMLCredential() {
    return samlCredential;
  }

  public void setSAMLCredential(SAMLCredential samlCredential) {
    this.samlCredential = samlCredential;
  }

  public AuthnRequest getAuthnRequest() {
    return authnRequest;
  }

  public String getRelayState() {
    return relayState;
  }
}
