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

import org.wso2.carbon.identity.governance.IdentityGovernanceService;

public class HIBPDataHolder {

    /**
     * Singleton instance of the HIBPDataHolder class.
     * This implements the Singleton pattern to ensure only one instance exists throughout the application.
     */
    private static final HIBPDataHolder INSTANCE = new HIBPDataHolder();

    /**
     * Reference to the IdentityGovernanceService.
     * This service provides governance capabilities for identity management operations
     * and is injected through OSGi declarative services.
     */
    private IdentityGovernanceService identityGovernanceService;

    /**
     * Private constructor to prevent instantiation from outside this class.
     * This enforces the Singleton pattern by making the constructor inaccessible.
     */
    private HIBPDataHolder() {
        // Private constructor to enforce singleton pattern
    }

    /**
     * Returns the singleton instance of HIBPDataHolder.
     *
     * @return The singleton instance of the HIBPDataHolder class
     */
    public static HIBPDataHolder getInstance() {
        return INSTANCE;
    }

    /**
     * Retrieves the current IdentityGovernanceService instance.
     * 
     * @return The IdentityGovernanceService instance that provides governance features
     */
    public IdentityGovernanceService getIdentityGovernanceService() {
        return identityGovernanceService;
    }

    /**
     * Sets the IdentityGovernanceService instance.
     * This method is called by the OSGi service component to inject the service reference.
     *
     * @param identityGovernanceService The IdentityGovernanceService instance to be used
     */
    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {
        this.identityGovernanceService = identityGovernanceService;
    }
}
