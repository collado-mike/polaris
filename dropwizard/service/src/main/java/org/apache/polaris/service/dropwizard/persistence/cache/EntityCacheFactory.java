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
package org.apache.polaris.service.dropwizard.persistence.cache;

import jakarta.inject.Inject;
import org.apache.polaris.core.context.CallContext;
import org.apache.polaris.core.context.RealmScoped;
import org.apache.polaris.core.persistence.PolarisMetaStoreManager;
import org.apache.polaris.core.persistence.cache.EntityCache;
import org.glassfish.hk2.api.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EntityCacheFactory implements Factory<EntityCache> {
  private static Logger LOGGER = LoggerFactory.getLogger(EntityCacheFactory.class);
  @Inject PolarisMetaStoreManager metaStoreManager;

  @RealmScoped
  @Override
  public EntityCache provide() {
    LOGGER.debug(
        "Creating new EntityCache instance for realm {}",
        CallContext.getCurrentContext().getRealmContext().getRealmIdentifier());
    return new EntityCache(metaStoreManager);
  }

  @Override
  public void dispose(EntityCache instance) {
    // no-op
  }
}
