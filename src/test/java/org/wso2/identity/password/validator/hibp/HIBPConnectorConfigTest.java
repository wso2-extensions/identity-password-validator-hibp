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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.identity.password.validator.hibp.util.Constants;

import java.util.Map;
import java.util.Properties;

/**
 * Tests for the HIBPConnectorConfig class.
 */
public class HIBPConnectorConfigTest {

    private HIBPConnectorConfig connectorConfig;

    @BeforeMethod
    public void setUp() {
        connectorConfig = new HIBPConnectorConfig();
    }

    /**
     * Test that the connector name is correctly returned.
     */
    @Test
    public void testGetName() {
        Assert.assertEquals(connectorConfig.getName(), Constants.CONNECTOR_NAME,
                "Connector name should match the constant");
    }

    /**
     * Test that the friendly name is correctly returned.
     */
    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(connectorConfig.getFriendlyName(), "Pwned Passwords",
                "Friendly name should be 'Pwned Passwords'");
    }

    /**
     * Test that the category is correctly returned.
     */
    @Test
    public void testGetCategory() {
        Assert.assertEquals(connectorConfig.getCategory(), "Password Policies",
                "Category should be 'Password Policies'");
    }

    /**
     * Test that the sub-category is correctly returned.
     */
    @Test
    public void testGetSubCategory() {
        Assert.assertEquals(connectorConfig.getSubCategory(), "DEFAULT",
                "Sub-category should be 'DEFAULT'");
    }

    /**
     * Test that the order is correctly returned.
     */
    @Test
    public void testGetOrder() {
        Assert.assertEquals(connectorConfig.getOrder(), 0,
                "Order should be 0");
    }

    /**
     * Test that the property names are correctly returned.
     */
    @Test
    public void testGetPropertyNames() {
        String[] propertyNames = connectorConfig.getPropertyNames();
        
        Assert.assertEquals(propertyNames.length, 2, "Should return 2 property names");
        Assert.assertEquals(propertyNames[0], Constants.CONNECTOR_ENABLE, "First property should be CONNECTOR_ENABLE");
        Assert.assertEquals(propertyNames[1], Constants.CONNECTOR_API_KEY, "Second property should be CONNECTOR_API_KEY");
    }

    /**
     * Test that the property name mapping is correctly returned.
     */
    @Test
    public void testGetPropertyNameMapping() {
        Map<String, String> nameMapping = connectorConfig.getPropertyNameMapping();
        
        Assert.assertEquals(nameMapping.size(), 2, "Should return 2 property name mappings");
        Assert.assertTrue(nameMapping.containsKey(Constants.CONNECTOR_ENABLE), "Should contain CONNECTOR_ENABLE key");
        Assert.assertTrue(nameMapping.containsKey(Constants.CONNECTOR_API_KEY), "Should contain CONNECTOR_API_KEY key");
        
        // Verify the friendly names are appropriate
        Assert.assertEquals(nameMapping.get(Constants.CONNECTOR_ENABLE), "Enable HaveIBeenPwned pwned password checker",
                "CONNECTOR_ENABLE should map to 'Enable HaveIBeenPwned pwned password checker'");
        Assert.assertEquals(nameMapping.get(Constants.CONNECTOR_API_KEY), "HaveIBeenPwned API key",
                "CONNECTOR_API_KEY should map to 'HaveIBeenPwned API key'");
    }

    /**
     * Test that the property description mapping is correctly returned.
     */
    @Test
    public void testGetPropertyDescriptionMapping() {
        Map<String, String> descMapping = connectorConfig.getPropertyDescriptionMapping();
        
        Assert.assertEquals(descMapping.size(), 2, "Should return 2 property description mappings");
        Assert.assertTrue(descMapping.containsKey(Constants.CONNECTOR_ENABLE), "Should contain CONNECTOR_ENABLE key");
        Assert.assertTrue(descMapping.containsKey(Constants.CONNECTOR_API_KEY), "Should contain CONNECTOR_API_KEY key");
        
        // Verify the descriptions are appropriate
        Assert.assertTrue(descMapping.get(Constants.CONNECTOR_ENABLE).contains("HaveIBeenPwned"),
                "CONNECTOR_ENABLE description should mention HaveIBeenPwned");
        Assert.assertTrue(descMapping.get(Constants.CONNECTOR_API_KEY).contains("API key"),
                "CONNECTOR_API_KEY description should mention API key");
    }

    /**
     * Test that the default properties are correctly returned.
     */
    @Test
    public void testGetDefaultPropertyValues() throws Exception {
        Properties properties = connectorConfig.getDefaultPropertyValues("carbon.super");
        
        Assert.assertEquals(properties.size(), 2, "Should return 2 default property values");
        Assert.assertEquals(properties.getProperty(Constants.CONNECTOR_ENABLE), "false", 
                "Default value for CONNECTOR_ENABLE should be 'false'");
        Assert.assertEquals(properties.getProperty(Constants.CONNECTOR_API_KEY), "", 
                "Default value for CONNECTOR_API_KEY should be empty string");
    }

    /**
     * Test the implementation of getDefaultPropertyValues with String[] and tenantDomain parameters.
     */
    @Test
    public void testGetDefaultPropertyValuesWithPropertyNames() throws Exception {
        String[] propertyNames = new String[]{
                Constants.CONNECTOR_ENABLE,
                Constants.CONNECTOR_API_KEY
        };
        
        Map<String, String> defaultValues = connectorConfig.getDefaultPropertyValues(propertyNames, "carbon.super");
        
        Assert.assertNotNull(defaultValues, "Default values map should not be null");
        // This method is expected to return an empty map as per current implementation
        Assert.assertEquals(defaultValues.size(), 0, "Should return an empty map");
    }
}
