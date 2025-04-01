/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.identity.password.validator.hibp;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.identity.password.validator.hibp.util.Constants;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * HIBP connector config implementation.
 * 
 * This class implements the IdentityConnectorConfig interface to provide configuration
 * for the HaveIBeenPwned (HIBP) password validator. It defines configuration properties
 * like enabling/disabling the validator and setting the API key required for HIBP service.
 * 
 * The connector allows WSO2 Identity Server to validate passwords against the HIBP database
 * of compromised passwords, enhancing security by preventing the use of known breached passwords.
 */
public class HIBPConnectorConfig implements IdentityConnectorConfig {

    /**
     * Returns the connector name used internally to identify this connector.
     * 
     * @return The internal name of the connector as defined in Constants.CONNECTOR_NAME
     */
    @Override
    public String getName() {
        return Constants.CONNECTOR_NAME;
    }

    /**
     * Returns the human-readable friendly name that will be displayed in the UI.
     * 
     * @return The display name for this connector
     */
    @Override
    public String getFriendlyName() {
        return "Pwned Passwords";
    }

    /**
     * Returns the category under which this connector will be grouped in the UI.
     * Places this connector under password policies section in the management console.
     * 
     * @return The category name for grouping this connector
     */
    @Override
    public String getCategory() {
        return "Password Policies";
    }

    /**
     * Returns the sub-category for additional grouping if needed.
     * Currently uses the default sub-category.
     * 
     * @return The sub-category name
     */
    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    /**
     * Determines the display order of this connector relative to others in the same category.
     * Lower numbers appear first in the UI.
     * 
     * @return The order priority as an integer
     */
    @Override
    public int getOrder() {
        return 0;
    }

    /**
     * Maps internal property names to user-friendly display names for the UI.
     * These names appear as labels in the management console.
     * 
     * @return A map of property keys to their display names
     */
    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(Constants.CONNECTOR_ENABLE, "Enable HaveIBeenPwned pwned password checker");
        nameMapping.put(Constants.CONNECTOR_API_KEY, "HaveIBeenPwned API key");
        return nameMapping;
    }

    /**
     * Provides descriptions for each property to help administrators understand their purpose.
     * These descriptions appear as help text in the management console.
     * 
     * @return A map of property keys to their descriptions
     */
    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(Constants.CONNECTOR_ENABLE, "Validate user passwords with HaveIBeenPwned pwned " +
                "password checker.");
        descriptionMapping.put(Constants.CONNECTOR_API_KEY, "API key for the HaveIBeenPwned service.");
        return descriptionMapping;
    }

    /**
     * Returns the list of property names that this connector supports.
     * These properties can be configured through the management console.
     * 
     * @return An array of property name strings
     */
    @Override
    public String[] getPropertyNames() {
        return new String[]{
                Constants.CONNECTOR_ENABLE,
                Constants.CONNECTOR_API_KEY
        };
    }

    /**
     * Provides default values for all properties when the connector is first initialized.
     * By default, the connector is disabled and no API key is set.
     * 
     * @param tenantDomain The tenant domain for which to get default properties
     * @return A Properties object containing the default values
     * @throws IdentityGovernanceException If an error occurs while getting default properties
     */
    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(Constants.CONNECTOR_ENABLE, "false");
        defaultProperties.put(Constants.CONNECTOR_API_KEY, "");
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    /**
     * Provides default property values for a specific set of properties and tenant domain.
     * Currently returns an empty map as it's not implemented specifically.
     * 
     * @param propertyNames An array of property names
     * @param tenantDomain The tenant domain
     * @return A map of property names to their default values
     * @throws IdentityGovernanceException If an error occurs while getting default properties
     */
    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain) 
            throws IdentityGovernanceException {
        return new HashMap<>();
    }
}
