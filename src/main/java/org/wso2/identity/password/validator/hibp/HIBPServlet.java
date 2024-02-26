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

package org.wso2.identity.password.validator.hibp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.identity.password.validator.hibp.util.Constants;
import org.wso2.identity.password.validator.hibp.util.Utils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * HIBP Servlet implementation.
 */
public class HIBPServlet extends HttpServlet {

    private static final long serialVersionUID = -7182121722709942000L;

    private static final Log LOG = LogFactory.getLog(HIBPServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (!StringUtils.isBlank(request.getParameter(Constants.TENANT_DOMAIN))) {
            // TODO: Validate the tenant.
            tenantDomain = request.getParameter(Constants.TENANT_DOMAIN).trim();
        }

        // Get HIBP connector status
        boolean isEnabled;
        try {
            isEnabled = HIBPService.isHIBPEnabled(tenantDomain);
        } catch (Exception e) {
            LOG.error("Failed to get status of HIBP connector.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        // Build response
        String responseString = Utils.buildStatusResponse(isEnabled);

        // Send response
        response.setContentType(Constants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        PrintWriter out = response.getWriter();
        out.print(responseString);
        out.flush();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Validate request
        if (StringUtils.isBlank(request.getParameter(Constants.PASSWORD_PARAM))) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (!StringUtils.isBlank(request.getParameter(Constants.TENANT_DOMAIN))) {
            //TODO Validate tenant
            tenantDomain = request.getParameter(Constants.TENANT_DOMAIN).trim();
        }

        // Get appearance count
        int passwordAppearanceCount;
        try {
            passwordAppearanceCount = HIBPService
                    .getPasswordAppearanceCount(request.getParameter(Constants.PASSWORD_PARAM), tenantDomain);
        } catch (Exception e) {
            LOG.error("Failed to get appearance count for the password.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        // Build response
        String responseString = Utils.buildResponse(passwordAppearanceCount);

        // Send response
        response.setContentType(Constants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        PrintWriter out = response.getWriter();
        out.print(responseString);
        out.flush();
    }
}
