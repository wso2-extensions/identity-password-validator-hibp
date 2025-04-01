/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.password.validator.hibp.util;

/**
 * Constants
 */
public class Constants {

    public static final String APPLICATION_JSON = "application/json";

    public static final String PASSWORD_PARAM = "password";

    public static final String COUNT_PARAM = "count";

    /**
     * Parameter name for enabling/disabling the HIBP validator
     */
    public static final String ENABLED_PARAM = "enabled";

    /**
     * Hashing algorithm used for password hashing
     */
    public static final String SHA1 = "SHA-1";

    /**
     * HTTP header name for the HIBP API key
     */
    public static final String HIBP_API_KEY_HEADER = "hibp-api-key";

    /**
     * Base URL for the HIBP password range API
     */
    public static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";

    /**
     * Servlet path for the HIBP validator endpoint
     */
    public static final String HIBP_SERVLET_PATH = "/hibp";

    /**
     * Name of the HIBP password validator connector
     */
    public static final String CONNECTOR_NAME = "hibp.password.validator";

    /**
     * Configuration property name for enabling/disabling the connector
     */
    public static final String CONNECTOR_ENABLE = CONNECTOR_NAME + ".enable";

    /**
     * Configuration property name for setting the HIBP API key
     */
    public static final String CONNECTOR_API_KEY = CONNECTOR_NAME + ".api.key";

    /**
     * Parameter name for tenant domain
     */
    public static final String TENANT_DOMAIN = "tenant_domain";

}
