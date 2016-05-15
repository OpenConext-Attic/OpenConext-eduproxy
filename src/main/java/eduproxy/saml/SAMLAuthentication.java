package eduproxy.saml;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;

public class SAMLAuthentication implements Authentication {

  private final SAMLPrincipal principal;
  private final Collection<? extends GrantedAuthority> authorities;

  public SAMLAuthentication(SAMLPrincipal principal) {
    this.principal = principal;
    authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {

    return this.authorities;
  }

  @Override
  public Object getCredentials() {
    return "N/A";
  }

  @Override
  public Object getDetails() {
    return principal;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }

  @Override
  public boolean isAuthenticated() {
    return false;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException("Not allowed");
  }

  @Override
  public String getName() {
    return principal.getName();
  }
}
