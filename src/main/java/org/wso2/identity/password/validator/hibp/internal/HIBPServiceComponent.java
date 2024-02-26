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

package org.wso2.identity.password.validator.hibp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.identity.password.validator.hibp.HIBPConnectorConfig;
import org.wso2.identity.password.validator.hibp.HIBPServlet;
import org.wso2.identity.password.validator.hibp.util.Constants;

import javax.servlet.Servlet;

/**
 * HIBP service component
 */
@Component(name = "org.wso2.hibp.connector",
        immediate = true)
public class HIBPServiceComponent {

    private static final Log log = LogFactory.getLog(HIBPServiceComponent.class);
    private HttpService httpService;

    @Activate
    protected void activate(ComponentContext context) {

        Servlet commonAuthServlet = new ContextPathServletAdaptor(new HIBPServlet(),
                Constants.HIBP_SERVLET_PATH);

        try {
            httpService.registerServlet(Constants.HIBP_SERVLET_PATH, commonAuthServlet, null, null);

            IdentityConnectorConfig connectorConfig = new HIBPConnectorConfig();
            context.getBundleContext().registerService(IdentityConnectorConfig.class, connectorConfig, null);
        } catch (Exception e) {
            throw new RuntimeException("Failed to start HIBP component.", e);
        }

        log.info("Successfully stated HIBP compoenent.");
    }

    @Reference(
            name = "osgi.httpservice",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the hibp bundle");
        }

        this.httpService = httpService;
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the hibp bundle");
        }

        this.httpService = null;
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        HIBPDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        HIBPDataHolder.getInstance().setIdentityGovernanceService(null);
    }
}
