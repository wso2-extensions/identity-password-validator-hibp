/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.hibp.connector.util;

/**
 * Constants
 */
public class Constants {

    public static final String APPLICATION_JSON = "application/json";

    public static final String PASSWORD_PARAM = "password";

    public static final String COUNT_PARAM = "count";

    public static final String ENABLED_PARAM = "enabled";

    public static final String SHA1 = "SHA-1";

    public static final String HIBP_API_KEY_HEADER = "hibp-api-key";

    public static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";

    public static final String HIBP_SERVLET_PATH = "/hibp";

    public static final String CONNECTOR_NAME = "hibp.password.validator";

    public static final String CONNECTOR_ENABLE = CONNECTOR_NAME + ".enable";

    public static final String CONNECTOR_API_KEY = CONNECTOR_NAME + ".api.key";

    public static final String TENANT_DOMAIN = "tenant_domain";

}
