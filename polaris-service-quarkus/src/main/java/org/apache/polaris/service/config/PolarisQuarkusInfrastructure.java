/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.polaris.service.config;

import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Default;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;
import jakarta.ws.rs.core.Context;
import java.time.Clock;
import java.util.HashMap;
import org.apache.polaris.core.PolarisConfigurationStore;
import org.apache.polaris.core.PolarisDefaultDiagServiceImpl;
import org.apache.polaris.core.PolarisDiagnostics;
import org.apache.polaris.core.auth.AuthenticatedPolarisPrincipal;
import org.apache.polaris.core.auth.PolarisAuthorizer;
import org.apache.polaris.core.auth.PolarisAuthorizerImpl;
import org.apache.polaris.core.context.CallContext;
import org.apache.polaris.core.context.RealmContext;
import org.apache.polaris.core.persistence.MetaStoreManagerFactory;
import org.apache.polaris.core.storage.cache.StorageCredentialCache;
import org.apache.polaris.service.auth.Authenticator;
import org.apache.polaris.service.auth.KeyProvider;
import org.apache.polaris.service.auth.TokenBrokerFactory;
import org.apache.polaris.service.catalog.api.IcebergRestOAuth2ApiService;
import org.apache.polaris.service.catalog.io.FileIOFactory;
import org.apache.polaris.service.context.CallContextResolver;
import org.apache.polaris.service.context.RealmContextResolver;
import org.apache.polaris.service.ratelimiter.RateLimiter;

public class PolarisQuarkusInfrastructure {

  @Produces
  public Clock clock() {
    return Clock.systemDefaultZone();
  }

  // Polaris core beans - application scope

  @Produces
  public StorageCredentialCache storageCredentialCache() {
    return new StorageCredentialCache();
  }

  @Produces
  public PolarisAuthorizer polarisAuthorizer(PolarisConfigurationStore configurationStore) {
    return new PolarisAuthorizerImpl(configurationStore);
  }

  @Produces
  public PolarisDiagnostics polarisDiagnostics() {
    return new PolarisDefaultDiagServiceImpl();
  }

  // Polaris core beans - request scope

  @Produces
  @RequestScoped
  public RealmContext realmContext(
      @Context HttpServerRequest request, RealmContextResolver realmContextResolver) {
    return realmContextResolver.resolveRealmContext(
        request.absoluteURI(),
        request.method().name(),
        request.path(),
        request.params().entries().stream()
            .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), HashMap::putAll),
        request.headers().entries().stream()
            .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), HashMap::putAll));
  }

  @Produces
  @RequestScoped
  public CallContext callContext(
      RealmContext realmContext,
      @Context HttpServerRequest request,
      CallContextResolver callContextResolver) {
    return callContextResolver.resolveCallContext(
        realmContext,
        request.method().name(),
        request.path(),
        request.params().entries().stream()
            .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), HashMap::putAll),
        request.headers().entries().stream()
            .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), HashMap::putAll));
  }

  // Polaris service beans - application scoped - selected from @RuntimeCandidate-annotated beans

  @Produces
  @Default
  public CallContextResolver callContextResolver(
      @RuntimeCandidate Instance<CallContextResolver> callContextResolvers) {
    return callContextResolvers.get();
  }

  @Produces
  @Default
  public RealmContextResolver realmContextResolver(
      @RuntimeCandidate Instance<RealmContextResolver> realmContextResolvers) {
    return realmContextResolvers.get();
  }

  @Produces
  @Default
  public FileIOFactory fileIOFactory(@RuntimeCandidate Instance<FileIOFactory> fileIOFactories) {
    return fileIOFactories.get();
  }

  @Produces
  @Default
  public MetaStoreManagerFactory metaStoreManagerFactory(
      @RuntimeCandidate Instance<MetaStoreManagerFactory> metaStoreManagerFactories) {
    return metaStoreManagerFactories.get();
  }

  @Produces
  @Default
  public RateLimiter rateLimiter(@RuntimeCandidate Instance<RateLimiter> rateLimiters) {
    return rateLimiters.get();
  }

  @Produces
  @Default
  public Authenticator<String, AuthenticatedPolarisPrincipal> authenticator(
      @RuntimeCandidate
          Instance<Authenticator<String, AuthenticatedPolarisPrincipal>> authenticators) {
    return authenticators.get();
  }

  @Produces
  @Default
  public KeyProvider keyProvider(@RuntimeCandidate Instance<KeyProvider> keyProviders) {
    return keyProviders.get();
  }

  @Produces
  @Default
  public TokenBrokerFactory tokenBrokerFactory(
      @RuntimeCandidate Instance<TokenBrokerFactory> tokenBrokerFactories) {
    return tokenBrokerFactories.get();
  }

  @Produces
  @Default
  public IcebergRestOAuth2ApiService icebergRestOAuth2ApiService(
      @RuntimeCandidate Instance<IcebergRestOAuth2ApiService> services) {
    return services.get();
  }
}
