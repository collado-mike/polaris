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

import com.auth0.jwt.algorithms.Algorithm;
import java.util.function.Supplier;
import org.apache.polaris.core.PolarisCallContext;
import org.apache.polaris.core.persistence.PolarisEntityManager;

/** Generates a JWT using a Symmetric Key. */
public class JWTSymmetricKeyBroker extends JWTBroker {
  private final Supplier<String> secretSupplier;

  JWTSymmetricKeyBroker(
      PolarisEntityManager entityManager,
      PolarisCallContext polarisCallContext,
      int maxTokenGenerationInSeconds,
      Supplier<String> secretSupplier) {
    super(entityManager, polarisCallContext, maxTokenGenerationInSeconds);
    this.secretSupplier = secretSupplier;
  }

  @Override
  Algorithm getAlgorithm() {
    return Algorithm.HMAC256(secretSupplier.get());
  }
}