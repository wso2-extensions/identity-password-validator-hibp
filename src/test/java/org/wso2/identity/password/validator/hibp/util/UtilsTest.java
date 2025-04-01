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

package org.wso2.identity.password.validator.hibp.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Map;

/**
 * Tests for the HIBP Utils class.
 */
public class UtilsTest {

    /**
     * Test buildResponse method that creates JSON response with password appearance count.
     */
    @Test
    public void testBuildResponse() {
        String response = Utils.buildResponse(42);
        
        // Parse the response and verify the count is correct
        JsonElement jsonElement = new JsonParser().parse(response);
        int count = jsonElement.getAsJsonObject()
                .get(Constants.COUNT_PARAM)
                .getAsInt();
        
        Assert.assertEquals(count, 42, "Password appearance count in response should match the input");
    }

    /**
     * Test buildStatusResponse method that creates JSON response for enabled status.
     */
    @Test
    public void testBuildStatusResponse() {
        // Test enabled status
        String enabledResponse = Utils.buildStatusResponse(true);
        JsonElement enabledJsonElement = new JsonParser().parse(enabledResponse);
        boolean enabledValue = enabledJsonElement.getAsJsonObject()
                .get(Constants.ENABLED_PARAM)
                .getAsBoolean();
        
        Assert.assertTrue(enabledValue, "Enabled status in response should be true");
        
        // Test disabled status
        String disabledResponse = Utils.buildStatusResponse(false);
        JsonElement disabledJsonElement = new JsonParser().parse(disabledResponse);
        boolean disabledValue = disabledJsonElement.getAsJsonObject()
                .get(Constants.ENABLED_PARAM)
                .getAsBoolean();
        
        Assert.assertFalse(disabledValue, "Enabled status in response should be false");
    }

    /**
     * Test getSHA1 method that hashes passwords.
     */
    @Test
    public void testGetSHA1() throws Exception {
        // Test with a known password and its expected SHA-1 hash
        String password = "password123";
        String expectedHash = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"; // SHA-1 for "password123"
        
        String hash = Utils.getSHA1(password);
        
        Assert.assertEquals(hash, expectedHash, "SHA-1 hash should match expected value");
    }

    /**
     * Test buildResponseMap method by providing a sample HIBP API response.
     */
    @Test
    public void testBuildResponseMap() {
        // Example HIBP API response format (hash suffix:count pairs)
        String mockResponse = 
                "0123456789ABCDEF0123456789ABCDEF01234567:3\r\n" +
                "ABCDEF0123456789ABCDEF0123456789ABCDEF01:42\r\n" +
                "FEDCBA9876543210FEDCBA9876543210FEDCBA98:1337";

        // Use reflection to access the private method for testing
        try {
            java.lang.reflect.Method method = Utils.class.getDeclaredMethod("buildResponseMap", String.class);
            method.setAccessible(true);
            
            @SuppressWarnings("unchecked")
            Map<String, Integer> resultMap = (Map<String, Integer>) method.invoke(null, mockResponse);
            
            // Verify the map contains correct entries
            Assert.assertEquals(resultMap.size(), 3, "Response map should contain 3 entries");
            Assert.assertEquals(resultMap.get("0123456789ABCDEF0123456789ABCDEF01234567"), Integer.valueOf(3));
            Assert.assertEquals(resultMap.get("ABCDEF0123456789ABCDEF0123456789ABCDEF01"), Integer.valueOf(42));
            Assert.assertEquals(resultMap.get("FEDCBA9876543210FEDCBA9876543210FEDCBA98"), Integer.valueOf(1337));
        } catch (Exception e) {
            Assert.fail("Failed to test buildResponseMap: " + e.getMessage());
        }
    }

    /**
     * Test that getSHA1 method handles empty input properly.
     */
    @Test
    public void testGetSHA1WithEmptyString() throws Exception {
        String emptyPassword = "";
        String expectedHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"; // SHA-1 for empty string
        
        String hash = Utils.getSHA1(emptyPassword);
        
        Assert.assertEquals(hash, expectedHash, "SHA-1 hash for empty string should match expected value");
    }

    /**
     * Test that buildResponseMap handles empty input properly.
     */
    @Test
    public void testBuildResponseMapWithEmptyResponse() {
        try {
            java.lang.reflect.Method method = Utils.class.getDeclaredMethod("buildResponseMap", String.class);
            method.setAccessible(true);
            
            // Test with empty response
            @SuppressWarnings("unchecked")
            Map<String, Integer> resultMap = (Map<String, Integer>) method.invoke(null, "");
            
            Assert.assertEquals(resultMap.size(), 0, "Response map should be empty for empty input");
        } catch (Exception e) {
            Assert.fail("Failed to test buildResponseMap with empty response: " + e.getMessage());
        }
    }

    /**
     * Test that buildResponseMap handles malformed input properly.
     */
    @Test
    public void testBuildResponseMapWithMalformedResponse() {
        try {
            java.lang.reflect.Method method = Utils.class.getDeclaredMethod("buildResponseMap", String.class);
            method.setAccessible(true);
            
            // Test with malformed response (missing count)
            @SuppressWarnings("unchecked")
            Map<String, Integer> resultMap = (Map<String, Integer>) method.invoke(null, "0123456789ABCDEF0123456789ABCDEF01234567");
            
            Assert.assertEquals(resultMap.size(), 0, "Response map should be empty for malformed input");
        } catch (Exception e) {
            Assert.fail("Failed to test buildResponseMap with malformed response: " + e.getMessage());
        }
    }
}