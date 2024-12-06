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
package org.apache.polaris.service.auth;

import io.dropwizard.auth.Authenticator;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.iceberg.exceptions.NotAuthorizedException;
import org.apache.polaris.core.PolarisCallContext;
import org.apache.polaris.core.auth.AuthenticatedPolarisPrincipal;
import org.apache.polaris.core.auth.PolarisGrantManager;
import org.apache.polaris.core.context.CallContext;
import org.apache.polaris.core.context.RealmContext;
import org.apache.polaris.core.entity.PolarisEntity;
import org.apache.polaris.core.entity.PolarisEntitySubType;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.apache.polaris.core.entity.PrincipalEntity;
import org.apache.polaris.core.entity.PrincipalRoleEntity;
import org.apache.polaris.core.persistence.MetaStoreManagerFactory;
import org.apache.polaris.core.persistence.PolarisMetaStoreManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base implementation of {@link DiscoverableAuthenticator} constructs a {@link
 * AuthenticatedPolarisPrincipal} from the token parsed by subclasses. The {@link
 * AuthenticatedPolarisPrincipal} is read from the {@link PolarisMetaStoreManager} for the current
 * {@link RealmContext}. If the token defines a non-empty set of scopes, only the principal roles
 * specified in the scopes will be active for the current principal. Only the grants assigned to
 * these roles will be active in the current request.
 */
public abstract class BasePolarisAuthenticator
    implements Authenticator<String, AuthenticatedPolarisPrincipal> {
  public static final String PRINCIPAL_ROLE_ALL = "PRINCIPAL_ROLE:ALL";
  public static final String PRINCIPAL_ROLE_PREFIX = "PRINCIPAL_ROLE:";
  private static final Logger LOGGER = LoggerFactory.getLogger(BasePolarisAuthenticator.class);

  @Inject protected MetaStoreManagerFactory metaStoreManagerFactory;
  @Inject private Provider<RealmContext> realmContext;
  @Inject private Provider<PolarisGrantManager> polarsGrantManagerProvider;

  public PolarisCallContext getCurrentPolarisContext() {
    return CallContext.getCurrentContext().getPolarisCallContext();
  }

  protected Optional<AuthenticatedPolarisPrincipal> getPrincipal(DecodedToken tokenInfo) {
    LOGGER.debug("Resolving principal for tokenInfo client_id={}", tokenInfo.getClientId());
    PolarisMetaStoreManager metaStoreManager =
        metaStoreManagerFactory.getOrCreateMetaStoreManager(realmContext.get());
    PolarisEntity principal;
    PolarisCallContext polarisContext = getCurrentPolarisContext();
    try {
      principal =
          tokenInfo.getPrincipalId() > 0
              ? PolarisEntity.of(
                  metaStoreManager.loadEntity(polarisContext, 0L, tokenInfo.getPrincipalId()))
              : PolarisEntity.of(
                  metaStoreManager.readEntityByName(
                      polarisContext,
                      null,
                      PolarisEntityType.PRINCIPAL,
                      PolarisEntitySubType.NULL_SUBTYPE,
                      tokenInfo.getSub()));
    } catch (Exception e) {
      LOGGER
          .atError()
          .addKeyValue("errMsg", e.getMessage())
          .addKeyValue("stackTrace", ExceptionUtils.getStackTrace(e))
          .log("Unable to authenticate user with token");
      throw new NotAuthorizedException("Unable to authenticate");
    }
    if (principal == null) {
      LOGGER.warn(
          "Failed to resolve principal from tokenInfo client_id={}", tokenInfo.getClientId());
      throw new NotAuthorizedException("Unable to authenticate");
    }

    List<PrincipalRoleEntity> activeRoles =
        loadActivePrincipalRoles(tokenInfo, principal, metaStoreManager);
    LOGGER.debug("Resolved principal: {}", principal);

    AuthenticatedPolarisPrincipal authenticatedPrincipal =
        new AuthenticatedPolarisPrincipal(new PrincipalEntity(principal), activeRoles);
    LOGGER.debug("Populating authenticatedPrincipal into CallContext: {}", authenticatedPrincipal);
    CallContext.getCurrentContext()
        .contextVariables()
        .put(CallContext.AUTHENTICATED_PRINCIPAL, authenticatedPrincipal);
    return Optional.of(authenticatedPrincipal);
  }

  protected List<PrincipalRoleEntity> loadActivePrincipalRoles(
      DecodedToken tokenInfo, PolarisEntity principal, PolarisMetaStoreManager metaStoreManager) {
    Set<String> tokenRoles =
        Optional.ofNullable(tokenInfo.getScope()).map(s -> Set.of(s.split(" "))).orElseGet(Set::of);
    PolarisCallContext polarisContext = getCurrentPolarisContext();
    PolarisGrantManager.LoadGrantsResult principalGrantResults =
        polarsGrantManagerProvider.get().loadGrantsToGrantee(polarisContext, principal);
    polarisContext
        .getDiagServices()
        .check(
            principalGrantResults.isSuccess(),
            "Failed to resolve principal roles for principal name={} id={}",
            principal.getName(),
            principal.getId());
    if (!principalGrantResults.isSuccess()) {
      LOGGER.warn(
          "Failed to resolve principal roles for principal name={} id={}",
          principal.getName(),
          principal.getId());
      throw new NotAuthorizedException("Unable to authenticate");
    }
    if (tokenRoles.contains(PRINCIPAL_ROLE_ALL)) {
      return List.of(AuthenticatedPolarisPrincipal.POLARIS_ROLE_ALL);
    }
    boolean allRoles = tokenRoles.contains(PRINCIPAL_ROLE_ALL);
    Predicate<PrincipalRoleEntity> includeRoleFilter =
        allRoles ? r -> true : r -> tokenRoles.contains(r.getName());
    List<PrincipalRoleEntity> activeRoles =
        principalGrantResults.getGrantRecords().stream()
            .map(
                gr ->
                    metaStoreManager.loadEntity(
                        polarisContext, gr.getSecurableCatalogId(), gr.getSecurableId()))
            .filter(PolarisMetaStoreManager.EntityResult::isSuccess)
            .map(PolarisMetaStoreManager.EntityResult::getEntity)
            .map(PrincipalRoleEntity::of)
            .filter(includeRoleFilter)
            .toList();
    if (activeRoles.size() != principalGrantResults.getGrantRecords().size()) {
      LOGGER
          .atWarn()
          .addKeyValue("principal", principal.getName())
          .addKeyValue("scopes", tokenRoles)
          .addKeyValue("roles", activeRoles)
          .log("Some principal roles were not found in the principal's grants");
    }
    return activeRoles;
  }
}
