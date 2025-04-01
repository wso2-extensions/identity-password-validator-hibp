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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;
import org.wso2.identity.password.validator.hibp.util.Utils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the HIBPService class.
 */
@PrepareForTest({Utils.class})
public class HIBPServiceTest extends PowerMockTestCase {

    private MockedStatic<Utils> mockedUtils;

    @BeforeMethod
    public void setUp() {
        mockedUtils = Mockito.mockStatic(Utils.class);
    }

    @AfterMethod
    public void tearDown() {
        mockedUtils.close();
    }

    /**
     * Test getPasswordAppearanceCount when connector is enabled and password appears in breached data.
     */
    @Test
    public void testGetPasswordAppearanceCount_PasswordBreached() throws Exception {
        // Mocked SHA1 hash for "password123"
        String mockedHash = "CBF8CD1B8FF6840F67D7F5F5A17A4CF0D4B72D62";
        String firstFive = "CBF8C";
        String remaining = "D1B8FF6840F67D7F5F5A17A4CF0D4B72D62";
        
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("true"); // enabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue("api-key-12345"); // API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Mock Utils.getSHA1 to return our pre-calculated hash
        mockedUtils.when(() -> Utils.getSHA1(anyString())).thenReturn(mockedHash);
        
        // Mock the API response with a breach count of 42
        Map<String, Integer> apiResponse = new HashMap<>();
        apiResponse.put(remaining, 42);
        mockedUtils.when(() -> Utils.getHIBPAppearanceMap(anyString(), anyString())).thenReturn(apiResponse);
        
        // Call the method under test
        int result = HIBPService.getPasswordAppearanceCount("password123", "carbon.super");
        
        // Verify the result is as expected
        Assert.assertEquals(result, 42, "Password should have 42 breaches");
    }

    /**
     * Test getPasswordAppearanceCount when connector is enabled but password is not in breached data.
     */
    @Test
    public void testGetPasswordAppearanceCount_PasswordNotBreached() throws Exception {
        // Mocked SHA1 hash for a strong password
        String mockedHash = "AF5570F5A1810B7AF78CAF4BC70FE44865367892";
        String firstFive = "AF557";
        String remaining = "0F5A1810B7AF78CAF4BC70FE44865367892";
        
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("true"); // enabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue("api-key-12345"); // API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Mock Utils.getSHA1 to return our pre-calculated hash
        mockedUtils.when(() -> Utils.getSHA1(anyString())).thenReturn(mockedHash);
        
        // Mock the API response with an empty result (no breaches)
        Map<String, Integer> apiResponse = new HashMap<>();
        mockedUtils.when(() -> Utils.getHIBPAppearanceMap(anyString(), anyString())).thenReturn(apiResponse);
        
        // Call the method under test
        int result = HIBPService.getPasswordAppearanceCount("StrongP@ssw0rd!", "carbon.super");
        
        // Verify the result is as expected
        Assert.assertEquals(result, 0, "Strong password should have 0 breaches");
    }

    /**
     * Test getPasswordAppearanceCount when connector is disabled.
     */
    @Test
    public void testGetPasswordAppearanceCount_ConnectorDisabled() throws Exception {
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("false"); // disabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue("api-key-12345"); // API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Call the method under test
        int result = HIBPService.getPasswordAppearanceCount("password123", "carbon.super");
        
        // Verify the result is as expected (should be 0 when disabled)
        Assert.assertEquals(result, 0, "Password should have 0 breaches when connector is disabled");
        
        // Verify that getSHA1 and getHIBPAppearanceMap were not called
        mockedUtils.verify(() -> Utils.getSHA1(anyString()), Mockito.never());
        mockedUtils.verify(() -> Utils.getHIBPAppearanceMap(anyString(), anyString()), Mockito.never());
    }

    /**
     * Test getPasswordAppearanceCount when API key is blank.
     */
    @Test
    public void testGetPasswordAppearanceCount_BlankAPIKey() throws Exception {
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("true"); // enabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue(""); // Blank API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Call the method under test
        int result = HIBPService.getPasswordAppearanceCount("password123", "carbon.super");
        
        // Verify the result is as expected (should be 0 when API key is blank)
        Assert.assertEquals(result, 0, "Password should have 0 breaches when API key is blank");
        
        // Verify that getSHA1 and getHIBPAppearanceMap were not called
        mockedUtils.verify(() -> Utils.getSHA1(anyString()), Mockito.never());
        mockedUtils.verify(() -> Utils.getHIBPAppearanceMap(anyString(), anyString()), Mockito.never());
    }

    /**
     * Test isHIBPEnabled when connector is enabled.
     */
    @Test
    public void testIsHIBPEnabled_ConnectorEnabled() throws Exception {
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("true"); // enabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue("api-key-12345"); // API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Call the method under test
        boolean result = HIBPService.isHIBPEnabled("carbon.super");
        
        // Verify the result is as expected
        Assert.assertTrue(result, "HIBP connector should be enabled");
    }

    /**
     * Test isHIBPEnabled when connector is disabled.
     */
    @Test
    public void testIsHIBPEnabled_ConnectorDisabled() throws Exception {
        // Mock connector configuration
        Property[] connectorConfigs = new Property[2];
        connectorConfigs[0] = new Property();
        connectorConfigs[0].setValue("false"); // disabled
        connectorConfigs[1] = new Property();
        connectorConfigs[1].setValue("api-key-12345"); // API key
        
        // Mock Utils.getConnectorConfiguration to return our config
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(connectorConfigs);
        
        // Call the method under test
        boolean result = HIBPService.isHIBPEnabled("carbon.super");
        
        // Verify the result is as expected
        Assert.assertFalse(result, "HIBP connector should be disabled");
    }

    /**
     * Test isHIBPEnabled with null connector configuration.
     */
    @Test
    public void testIsHIBPEnabled_NullConfig() throws Exception {
        // Mock Utils.getConnectorConfiguration to return null
        mockedUtils.when(() -> Utils.getConnectorConfiguration(anyString())).thenReturn(null);
        
        // Call the method under test
        boolean result = HIBPService.isHIBPEnabled("carbon.super");
        
        // Verify the result is as expected
        Assert.assertFalse(result, "HIBP connector should be disabled when config is null");
    }
}
