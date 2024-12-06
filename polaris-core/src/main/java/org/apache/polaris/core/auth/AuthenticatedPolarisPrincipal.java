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
package org.apache.polaris.core.auth;

import jakarta.annotation.Nonnull;
import java.util.List;
import org.apache.polaris.core.entity.PolarisEntity;
import org.apache.polaris.core.entity.PrincipalRoleEntity;

/** Holds the results of request authentication. */
public class AuthenticatedPolarisPrincipal implements java.security.Principal {
  private final PolarisEntity principalEntity;
  private List<PrincipalRoleEntity> activatedPrincipalRoles;

  public static final PrincipalRoleEntity POLARIS_ROLE_ALL =
      new PrincipalRoleEntity.Builder().setId(Long.MAX_VALUE).setName("ALL").build();

  public AuthenticatedPolarisPrincipal(
      @Nonnull PolarisEntity principalEntity,
      @Nonnull List<PrincipalRoleEntity> activatedPrincipalRoles) {
    this.principalEntity = principalEntity;
    this.activatedPrincipalRoles = activatedPrincipalRoles;
  }

  @Override
  public String getName() {
    return principalEntity.getName();
  }

  public PolarisEntity getPrincipalEntity() {
    return principalEntity;
  }

  public List<PrincipalRoleEntity> getActivatedPrincipalRoles() {
    return activatedPrincipalRoles;
  }

  public void setActivatedPrincipalRoles(List<PrincipalRoleEntity> activatedPrincipalRoles) {
    this.activatedPrincipalRoles = activatedPrincipalRoles;
  }

  @Override
  public String toString() {
    return "principalEntity="
        + getPrincipalEntity()
        + ";activatedPrincipalRoles="
        + getActivatedPrincipalRoles();
  }
}
