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

package org.wso2.carbon.identity.application.authenticator.totp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorImpl;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.concurrent.TimeUnit;

/**
 * TOTP Token verifier class.
 */
public class TOTPTokenVerifier {

    private static Log log = LogFactory.getLog(TOTPTokenVerifier.class);

    /**
     * Verify whether a given token is valid for a stored local user.
     *
     * @param token    TOTP Token
     * @param context  Authentication context.
     * @param username Username of the user
     * @return true if token is valid otherwise false
     * @throws TOTPException
     */
    public static boolean isValidTokenLocalUser(int token, String username, AuthenticationContext context)
            throws TOTPException {
        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
        long timeStep;
        int windowSize;
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        try {
            if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod(tenantDomain, context))) {
                encoding = TOTPKeyRepresentation.BASE64;
            }
            timeStep = TimeUnit.SECONDS.toMillis(TOTPUtil.getTimeStepSize(context));
            windowSize = TOTPUtil.getWindowSize(context);
            TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder totpAuthenticatorConfigBuilder = new
                    TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder()
                    .setKeyRepresentation(encoding)
                    .setWindowSize(windowSize)
                    .setTimeStepSizeInMillis(timeStep);
            TOTPAuthenticatorImpl totpAuthenticator = new TOTPAuthenticatorImpl(totpAuthenticatorConfigBuilder.build());
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = TOTPDataHolder.getInstance().getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                String secretKey = TOTPUtil.decrypt(userStoreManager.getUserClaimValue(username,
                        TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null));
                return totpAuthenticator.authorize(secretKey, token);
            } else {
                throw new TOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPTokenVerifier failed while trying to access userRealm of the user : " +
                    username, e);
        } catch (CryptoException e) {
            throw new TOTPException("Error while decrypting the key", e);
        }
    }
}