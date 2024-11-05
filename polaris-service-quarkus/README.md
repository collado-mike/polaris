<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at
 
   http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

This module contains the Polaris Service powered by Quarkus (instead of Dropwizard as in `polaris-service`).
This module contains the Polaris Service (server) 

# Main differences

| Feature | Support in Quarkus | Support in Dropwizard | Impact |
| --------| -------------------|-----------------------|-------------------|
| CDI     | [built-in](https://quarkus.io/guides/cdi-reference) - index generated at build time | [supported with hk2](https://www.dropwizard.io/en/stable/manual/di.html) | Equal effort to migrate to annotations - possible complications with build-time dependency scanning |
| Metrics | supported using Prometheus _simple client_ (must be enabled at build time) | manually updated to later prometheus API | Need to port updated Prometheus client to work in Quarkus |
| health check | Health check framework supported - need to implement health checkers | Existing health checker - needs to integrate with persistence, etc. | Equal support |
| `@Timed` annotation | Supported with built-in micrometer | `@TimedApi` implemented due to custom requirements | Need to port existing behavior |
| json layout | basic json logging support | custom json layout implemented for support for key/value pairs | Need to port custom json layout behavior |
| PolarisApplication | not needed | needed | can drop one extra class |
| Cors | supported via config | supported with custom code | can drop extra cors code |
| configuration | application.properties | application.yaml | significant effort to migrate - maps and lists supported? |
| Performance | improved | baseline | better startup performance |
| Custom json ser/de | ??? | currently implemented | unknown|


* Bean injection (CDI) is made using `@ApplicationScoped` annotation on class and injected in other classes using `@Inject` annotation (https://quarkus.io/guides/cdi-reference). Dropwizard injection json 
* Codehale metrics registry and opentelemetry boilerplate (prometheus exporter included) are not needed anymore: Quarkus provides it "out of the box" (https://quarkus.io/guides/opentelemetry)
* `PolarisHealthCheck` is not needed anymore: Quarkus provides it "out of the box" (https://quarkus.io/guides/smallrye-health)
* `TimedApplicationEventListener` and the `@TimedApi` annotation are replaced by Quarkus (micrometer) `@Timed` annotation (https://quarkus.io/guides/telemetry-micrometer)
* `PolarisJsonLayoutFactory` is not needed anymore: Quarkus provides it by configuration (using `quarkus.log.*` configuration)
* `PolarisApplication` is not needed, Quarkus provide a "main" application out of the box (it's possible to provide `QuarkusApplication` for control the startup and also using `@Startup` annotation)
* CORS boilerplate is not needed anymore: Quarkus supports it via configuration (using `quarkus.http.cors.*` configuration)
* CLI is not part of `polaris-service` anymore, we have (will have) a dedicated module (`polaris-cli`)

# Build and run

To build `polaris-service-quarkus` you simply do:

```
./gradlew :polaris-service-quarkus:build
```

The build creates ready to run package:
* in the `build/quarkus-app` folder, you can run with `java -jar quarkus-run.jar`
* the `build/distributions` folder contains tar/zip distributions you can extract  

You can directly run Polaris service (in the build scope) using:

```
./gradlew :polaris-service-quarkus:quarkusRun
```

You can directly build a Docker image using:

```
./gradlew :polaris-service-quarkus:imageBuild
```

# Configuration

The main configuration file is not the `application.properties`. The default configuration is package as part of the `polaris-service-quarkus`.
`polaris-service-quarkus` uses several configuration sources (in this order):
* system properties
* environment variables
* `.env` file in the current working directory
* `$PWD/config/application.properties` file
* the `application.properties` packaged in the `polaris-service-quarkus` application

It means you can override some configuration property using environment variables for example.

By default, `polaris-service-quarkus` uses 8181 as HTTP port (defined in the `quarkus.http.port` configuration property).

You can override it with, for example if you want to use 8282 port number:

```
export QUARKUS_HTTP_PORT=8282 ; java -jar build/quarkus-app/quarkus-run.jar
```

You can find more details here: https://quarkus.io/guides/config

# TODO

* Modify `CallContext` and remove all usages of ThreadLocal, replace with proper context propagation.
* Complete utests/itests in `polaris-service-quarkus`
* Remove dropwizard references (in `polaris-core` and `polaris-service-quarkus`)
* Remove `@TimedApi` from `polaris-core` (`org.apache.polaris.core.resource.TimedApi`)
* Remove `polaris-service` and rename `polaris-service-quarkus` as `polaris-service`
* Create `polaris-cli` module
* Update documentation/README/...

* Do we want to support existing json configuration file as configuration source ?
