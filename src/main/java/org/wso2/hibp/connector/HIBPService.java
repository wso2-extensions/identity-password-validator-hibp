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

package org.wso2.hibp.connector;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.hibp.connector.util.Utils;

import java.util.Map;

/**
 * HIBP Service implementation.
 */
public class HIBPService {

    /**
     * Get password appearance count.
     *
     * @param password password.
     * @return appearance count.
     * @throws Exception in case of failure.
     */
    public static int getPasswordAppearanceCount(String password, String tenantDomain) throws Exception {

        Property[] connectorConfigs = Utils.getConnectorConfiguration(tenantDomain);

        // Connector is not enabled
        if (connectorConfigs == null || connectorConfigs.length != 2
                || !Boolean.parseBoolean(connectorConfigs[0].getValue())
                || StringUtils.isBlank(connectorConfigs[1].getValue())) {
            return 0;
        }

        String passwordHash = Utils.getSHA1(password);
        String firstFiveLettersOfHash = passwordHash.substring(0, 5);
        String remainingLettersOfHash = passwordHash.substring(5);

        Map<String, Integer> appearanceMap = Utils.getHIBPAppearanceMap(connectorConfigs[1].getValue(),
                firstFiveLettersOfHash);
        if (appearanceMap.isEmpty() || !appearanceMap.containsKey(remainingLettersOfHash)) {
            return 0;
        }
        return appearanceMap.get(remainingLettersOfHash);
    }

    /**
     * Check HIBP enabled
     *
     * @param tenantDomain tenant domain
     * @return true if enabled
     * @throws Exception in case of failure.
     */
    public static boolean isHIBPEnabled(String tenantDomain) throws Exception {

        Property[] connectorConfigs = Utils.getConnectorConfiguration(tenantDomain);

        // Connector is not enabled
        if (connectorConfigs == null || connectorConfigs.length != 2) {
            return false;
        }

        return Boolean.parseBoolean(connectorConfigs[0].getValue());
    }
}
