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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import static org.wso2.identity.password.validator.hibp.util.Constants.*;

/**
 * Utility class that provides helper methods for the HIBP (Have I Been Pwned) password validator.
 * Contains methods for building responses, computing SHA1 hashes, communicating with the HIBP API,
 * and retrieving connector configurations.
 */
public class Utils {

    /**
     * Builds a JSON response containing the number of times a password has appeared in data breaches.
     *
     * @param passwordAppearanceCount The number of times the password has appeared in known data breaches
     * @return JSON string containing the password appearance count
     */
    public static String buildResponse(int passwordAppearanceCount) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(COUNT_PARAM, passwordAppearanceCount);
        return new Gson().toJson(jsonObject);
    }

    /**
     * Builds a JSON response indicating whether the HIBP validator is enabled or disabled.
     *
     * @param isEnabled Boolean value indicating if the HIBP validator is enabled
     * @return JSON string containing the enabled status
     */
    public static String buildStatusResponse(boolean isEnabled) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(ENABLED_PARAM, isEnabled);
        return new Gson().toJson(jsonObject);
    }

    /**
     * Computes the SHA-1 hash of the provided value and returns it as an uppercase hex string.
     * This is used to safely check passwords against the HIBP API which uses the k-anonymity model.
     *
     * @param value The string value (password) to hash
     * @return Uppercase SHA-1 hash as a hexadecimal string (40 characters)
     * @throws Exception If the hashing operation fails
     */
    public static String getSHA1(String value) throws Exception {

        try {
            MessageDigest digest = MessageDigest.getInstance(SHA1);
            digest.reset();
            digest.update(value.getBytes(StandardCharsets.UTF_8));
            return String.format("%040x", new BigInteger(1, digest.digest())).toUpperCase();
        } catch (Exception e) {
            throw new Exception("Failed to build digest value", e);
        }
    }

    /**
     * Queries the HIBP API to check if the password has been exposed in a data breach.
     * Uses the k-anonymity model where only the first 5 characters of the hash are sent to the API.
     * 
     * The API returns a list of hash suffixes and their occurrence counts that match the provided prefix.
     *
     * @param apiKey The API key for authenticating with the HIBP service
     * @param firstFiveLettersOfHash The first 5 characters of the SHA-1 hash of the password
     * @return Map containing hash suffixes as keys and their breach occurrence counts as values
     * @throws Exception If the API request fails or returns an unexpected response
     */
    public static Map<String, Integer> getHIBPAppearanceMap(String apiKey, String firstFiveLettersOfHash) throws Exception {

        // Set up the API key header required by HIBP API
        Header apiKeyHeader = new BasicHeader(HIBP_API_KEY_HEADER, apiKey);
        List<Header> headers = new ArrayList<>();
        headers.add(apiKeyHeader);

        try (CloseableHttpClient httpclient =
                     HttpClientBuilder.create().useSystemProperties().setDefaultHeaders(headers).build()) {
            // Create GET request to the HIBP API with the hash prefix
            HttpGet httpGet = new HttpGet(HIBP_API_URL + firstFiveLettersOfHash);

            // Execute the request and check response status
            HttpResponse response = httpclient.execute(httpGet);
            if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
                throw new Exception("Failed to get HIBP API response.");
            }

            // Process the response entity
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                return Collections.emptyMap();
            }

            // Read the response content and build a map of hash suffixes to occurrence counts
            try (InputStream in = entity.getContent()) {
                return buildResponseMap(IOUtils.toString(in, StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * Parses the HIBP API response and builds a map of hash suffixes to their occurrence counts.
     * The response format is a series of lines with each line containing a hash suffix and count
     * separated by a colon (e.g., "1E4C9B93F3F0682250B6CF8331B7EE68D:3").
     *
     * @param response String content from the HIBP API response
     * @return Map with hash suffixes as keys and breach occurrence counts as values
     */
    private static Map<String, Integer> buildResponseMap(String response) {

        if (StringUtils.isBlank(response)) {
            return Collections.emptyMap();
        }

        Map<String, Integer> responseMap = new HashMap<>();
        String[] lines = response.split("\\r?\\n");
        for (String line : lines) {
            String[] elements = line.split(":");
            if (elements.length == 2) {
                responseMap.put(elements[0], Integer.parseInt(elements[1]));
            }
        }
        return responseMap;
    }

    /**
     * Retrieves the HIBP validator connector configuration properties for the specified tenant.
     * Gets both the enabled status and API key configurations.
     *
     * @param tenantDomain The domain of the tenant for which to retrieve the configuration
     * @return Array of configuration properties
     * @throws Exception If the configuration retrieval fails
     */
    public static Property[] getConnectorConfiguration(String tenantDomain) throws Exception {

        Property[] connectorConfigs;
        try {
            connectorConfigs =
                    HIBPDataHolder.getInstance().getIdentityGovernanceService().getConfiguration(new String[]{
                            CONNECTOR_ENABLE, CONNECTOR_API_KEY}, tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new Exception("Failed to load connector configurations.", e);
        }
        return connectorConfigs;
    }

}
