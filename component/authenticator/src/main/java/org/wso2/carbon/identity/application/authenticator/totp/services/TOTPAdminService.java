/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.totp.services;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPKeyGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.user.api.UserStoreException;

public class TOTPAdminService {

    private static Log log = LogFactory.getLog(TOTPAdminService.class);

    /**
     * Generate TOTP Token for a given user.
     *
     * @param username username of the user.
     * @param context  Authentication context.
     * @return
     * @throws TOTPException
     */
    public String initTOTP(String username, AuthenticationContext context) throws TOTPException, UserStoreException {
            return TOTPKeyGenerator.getQRCodeURL(username, false, context);

    }

    /**
     * reset TOTP credentials of the user
     *
     * @param username of the user
     * @return
     * @throws TOTPException
     */
    public boolean resetTOTP(String username) throws TOTPException {
        return TOTPKeyGenerator.resetLocal(username);
    }

    /**
     * Reset TOTP credentials of the user.
     *
     * @param username of the user.
     * @param context  Authentication context.
     * @return QR code url for refreshed secret key.
     * @throws TOTPException
     */
    public String refreshSecretKey(String username, AuthenticationContext context) throws TOTPException {
            return TOTPKeyGenerator.getQRCodeURL(username, true, context);
    }
}