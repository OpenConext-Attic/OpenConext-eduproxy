package eduproxy.web;

import eduproxy.saml.*;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private Environment environment;

  @Value("${idp.metadata_url}")
  private String identityProviderMetadataUrl;

  @Value("${idp.entity_id}")
  private String identityProviderEntityId;

  @Value("${idp.certificate}")
  private String surfConextPublicCertificate;

  @Value("${proxy.base_url}")
  private String serviceProviderBaseUrl;

  @Value("${proxy.entity_id}")
  private String serviceProviderEntityId;

  @Value("${proxy.private_key}")
  private String serviceProviderPrivateKey;

  @Value("${proxy.certificate}")
  private String serviceProviderCertificate;

  @Value("${proxy.passphrase}")
  private String serviceProviderPassphrase;

  @Value("${edugain.feed}")
  private String edugainFeedUrl;

  private DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider samlAuthenticationProvider = new ProxySAMLAuthenticationProvider();
    samlAuthenticationProvider.setUserDetails(new DefaultSAMLUserDetailsService());
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    samlAuthenticationProvider.setExcludeCredential(true);
    return samlAuthenticationProvider;
  }

  @Bean
  public SAMLEntryPoint samlEntryPoint() {
    WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
    webSSOProfileOptions.setIncludeScoping(false);

    SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
    samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
    return samlEntryPoint;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/health");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .httpBasic().authenticationEntryPoint(identityProviderAuthnFilter())
      .and()
      .csrf().disable()
      .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
      .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
      .authorizeRequests()
      .antMatchers("/saml/idp/**", "/sp/metadata", "/saml/SSO/**", "/idp/metadata").permitAll()
      .anyRequest().hasRole("USER");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(samlAuthenticationProvider());
  }

  @Bean
  public MetadataDisplayFilter metadataDisplayFilter() {
    DefaultMetadataDisplayFilter displayFilter = new DefaultMetadataDisplayFilter();
    displayFilter.setFilterProcessesUrl("sp/metadata");
    return displayFilter;
  }

  @Bean
  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    failureHandler.setUseForward(true);
    failureHandler.setDefaultFailureUrl("/error");
    return failureHandler;
  }

  @Bean
  @Autowired
  public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(new ProxyAuthenticationSuccessHandler(samlMessageHandler()));
    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOProcessingFilter;
  }

  @Bean
  @Autowired
  public MetadataGeneratorFilter metadataGeneratorFilter() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  public FilterChainProxy samlFilter() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(chain("/saml/idp/**", identityProviderAuthnFilter()));
    chains.add(chain("/saml/login/**", samlEntryPoint()));
    chains.add(chain("/sp/metadata/**", metadataDisplayFilter()));
    chains.add(chain("/saml/SSO/**", samlWebSSOProcessingFilter()));
    return new FilterChainProxy(chains);
  }

  @Bean
  public IdentityProviderAuthnFilter identityProviderAuthnFilter() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    return new IdentityProviderAuthnFilter(samlMessageHandler());
  }

  private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
    return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
  }

  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSignMetadata(false);
    return extendedMetadata;
  }

  @Bean
  public MetadataProvider identityProvider() throws MetadataProviderException {
    Resource resource = defaultResourceLoader.getResource(identityProviderMetadataUrl);
    ResourceMetadataProvider resourceMetadataProvider = new ResourceMetadataProvider(resource);
    resourceMetadataProvider.setParserPool(parserPool());
    ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceMetadataProvider, extendedMetadata());
    extendedMetadataDelegate.setMetadataTrustCheck(true);
    extendedMetadataDelegate.setMetadataRequireSignature(false);
    return extendedMetadataDelegate;
  }

  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata() throws MetadataProviderException {
    List<MetadataProvider> providers = new ArrayList<>();
    providers.add(identityProvider());

    return new CachingMetadataManager(providers);
  }

  @Bean
  public VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  @Bean(initMethod = "initialize")
  public StaticBasicParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  public ParserPoolHolder parserPoolHolder() {
    return new ParserPoolHolder();
  }

  @Bean
  public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
    return new MultiThreadedHttpConnectionManager();
  }

  @Bean
  public HttpClient httpClient() {
    return new HttpClient(multiThreadedHttpConnectionManager());
  }

  @Bean
  public static SAMLBootstrap sAMLBootstrap() {
    return new SAMLBootstrap();
  }

  @Bean
  public SAMLDefaultLogger samlLogger() {
    return new SAMLDefaultLogger();
  }

  @Bean
  public WebSSOProfileConsumer webSSOprofileConsumer() {
    return new WebSSOProfileConsumerImpl();
  }

  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
    return new WebSSOProfileConsumerHoKImpl();
  }

  @Bean
  public WebSSOProfile webSSOprofile() {
    return new WebSSOProfileImpl();
  }

  @Bean
  public WebSSOProfileECPImpl ecpprofile() {
    return new WebSSOProfileECPImpl();
  }

  @Bean
  public SAMLContextProviderImpl contextProvider() throws URISyntaxException {
    return new ProxiedSAMLContextProviderLB(new URI(serviceProviderBaseUrl));
  }

  @Bean
  public MetadataGenerator metadataGenerator() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    MetadataGenerator metadataGenerator = new MetadataGenerator();
    metadataGenerator.setEntityId(serviceProviderEntityId);
    metadataGenerator.setEntityBaseURL(serviceProviderBaseUrl);
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());
    if (environment.acceptsProfiles("dev")) {
      metadataGenerator.setWantAssertionSigned(false);
    }
    return metadataGenerator;
  }

  @Bean
  public KeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    KeyStoreLocator keyStoreLocator = new KeyStoreLocator();
    KeyStore keyStore = keyStoreLocator.createKeyStore(serviceProviderPassphrase);

    keyStoreLocator.addPrivateKey(keyStore, serviceProviderEntityId, serviceProviderPrivateKey, serviceProviderCertificate, serviceProviderPassphrase);
    keyStoreLocator.addCertificate(keyStore, identityProviderEntityId, serviceProviderCertificate);

    Map<String, String> serviceProviders = new EduGainFeedParser(defaultResourceLoader.getResource(edugainFeedUrl)).parse();
    serviceProviders.entrySet().forEach(sp -> {
      try {
        keyStoreLocator.addCertificate(keyStore, sp.getKey(), sp.getValue());
      } catch (CertificateException | KeyStoreException e) {
        throw new RuntimeException(e);
      }
    });
    return new JKSKeyManager(keyStore, Collections.singletonMap(serviceProviderEntityId, serviceProviderPassphrase), serviceProviderEntityId);
  }

  private ArtifactResolutionProfile artifactResolutionProfile() {
    final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
    return artifactResolutionProfile;
  }

  @Bean
  public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
    return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
  }

  @Bean
  public HTTPSOAP11Binding soapBinding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPostBinding httpPostBinding() {
    ParserPool parserPool = parserPool();
    HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine(), "/templates/saml2-post-binding.vm");
    return new HTTPPostBinding(parserPool, new HTTPPostDecoder(parserPool), encoder);
  }

  @Bean
  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
    return new HTTPRedirectDeflateBinding(parserPool());
  }

  @Bean
  public HTTPSOAP11Binding httpSOAP11Binding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPAOS11Binding httpPAOS11Binding() {
    return new HTTPPAOS11Binding(parserPool());
  }

  @Bean
  public SAMLProcessorImpl processor() {
    Collection<SAMLBinding> bindings = new ArrayList<>();
    bindings.add(httpRedirectDeflateBinding());
    bindings.add(httpPostBinding());
    bindings.add(artifactBinding(parserPool(), velocityEngine()));
    bindings.add(httpSOAP11Binding());
    bindings.add(httpPAOS11Binding());
    return new SAMLProcessorImpl(bindings);
  }

  @Bean
  public SAMLMessageHandler samlMessageHandler() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    return new SAMLMessageHandler(
      keyManager(),
      new HTTPRedirectDeflateDecoder(parserPool()),
      new HTTPPostSimpleSignEncoder(velocityEngine(), "/templates/saml2-post-simplesign-binding.vm", true),
      securityPolicyResolver(),
      serviceProviderEntityId);
  }

  private SecurityPolicyResolver securityPolicyResolver() {
    IssueInstantRule instantRule = new IssueInstantRule(90, 300);
    MessageReplayRule replayRule = new MessageReplayRule(new ReplayCache(new MapBasedStorageService(), 14400000));

    BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
    securityPolicy.getPolicyRules().addAll(Arrays.asList(instantRule, replayRule));

    return new StaticSecurityPolicyResolver(securityPolicy);
  }


}
