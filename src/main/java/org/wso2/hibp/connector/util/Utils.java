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
import org.wso2.hibp.connector.internal.HIBPDataHolder;

import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import static org.wso2.hibp.connector.util.Constants.*;

/**
 * Utils
 */
public class Utils {

    public static String buildResponse(int passwordAppearanceCount) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(COUNT_PARAM, passwordAppearanceCount);
        return new Gson().toJson(jsonObject);
    }

    public static String buildStatusResponse(boolean isEnabled) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(ENABLED_PARAM, isEnabled);
        return new Gson().toJson(jsonObject);
    }

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

    public static Map<String, Integer> getHIBPAppearanceMap(String apiKey, String firstFiveLettersOfHash) throws Exception {

        Header apiKeyHeader = new BasicHeader(HIBP_API_KEY_HEADER, apiKey);
        List<Header> headers = new ArrayList<>();
        headers.add(apiKeyHeader);

        try (CloseableHttpClient httpclient =
                     HttpClientBuilder.create().useSystemProperties().setDefaultHeaders(headers).build()) {
            HttpGet httpGet = new HttpGet(HIBP_API_URL + firstFiveLettersOfHash);

            HttpResponse response = httpclient.execute(httpGet);
            if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
                throw new Exception("Failed to get HIBP API response.");
            }

            HttpEntity entity = response.getEntity();
            if (entity == null) {
                return Collections.emptyMap();
            }

            try (InputStream in = entity.getContent()) {
                return buildResponseMap(IOUtils.toString(in));
            }
        }
    }

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
