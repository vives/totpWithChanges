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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.*;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * TOTP key generator class.
 */
public class TOTPKeyGenerator {

    private static Log log = LogFactory.getLog(TOTPKeyGenerator.class);

    /**
     * Generate TOTP secret key and QR Code url for local users.
     *
     * @param username username of the user
     * @param context  Authentication context.
     * @return QR code url.
     * @throws TOTPException
     */
    public static String getQRCodeURL(String username, boolean refresh, AuthenticationContext context)
            throws TOTPException {
        String secretKey;
        String encodedQRCodeURL = null;
        String encoding;
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = TOTPDataHolder.getInstance().getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                secretKey = userRealm.getUserStoreManager().getUserClaimValue(username,
                        TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null);
                if (StringUtils.isEmpty(secretKey) || refresh) {
                    TOTPAuthenticatorKey key = generateKey(username, tenantDomain, context);
                    secretKey = key.getKey();
                    encoding = TOTPUtil.getEncodingMethod(tenantDomain, context);
                    userRealm.getUserStoreManager().setUserClaimValue(username,
                            TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.encrypt(secretKey), null);
                    userRealm.getUserStoreManager().setUserClaimValue(username,
                            TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding, null);
                } else {
                    secretKey = TOTPUtil.decrypt(secretKey);
                }
                String qrCodeURL = "otpauth://totp/" + tenantDomain + ":" + username + "?secret=" + secretKey +
                        "&issuer=" + tenantDomain;
                encodedQRCodeURL = Base64.encodeBase64String(qrCodeURL.getBytes());
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPKeyGenerator failed while trying to access userRealm for the user : " +
                    username, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPKeyGenerator failed while decrypting", e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("TOTPKeyGenerator cannot find the property value for encoding method", e);
        }
        return encodedQRCodeURL;
    }

    /**
     * Remove the stored secret key , qr code url from user claims.
     *
     * @param username username of the user
     * @return true if the operation is successful, false otherwise
     * @throws TOTPException
     */
    public static boolean resetLocal(String username) throws TOTPException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = TOTPDataHolder.getInstance().getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                userRealm.getUserStoreManager().deleteUserClaimValue(username,
                        TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, null);
                userRealm.getUserStoreManager().deleteUserClaimValue(username,
                        TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, null);
                userRealm.getUserStoreManager().deleteUserClaimValue(username,
                        TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null);
                return true;
            } else {
                throw new TOTPException("Can not find the user realm for the given tenant domain : " + CarbonContext.
                        getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException("Can not find the user realm for the user : " + username, e);
        }
    }

    /**
     * Generate TOTPAuthenticator key
     *
     * @param context      Authentication context.
     * @param tenantDomain tenant domain.
     * @return TOTPAuthenticatorKey object
     */
    private static TOTPAuthenticatorKey generateKey(String username, String tenantDomain, AuthenticationContext context)
            throws TOTPException,
            AuthenticationFailedException {
        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
        if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod(tenantDomain, context))) {
            encoding = TOTPKeyRepresentation.BASE64;
        }
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder gacb = new TOTPAuthenticatorConfig
                .TOTPAuthenticatorConfigBuilder()
                .setKeyRepresentation(encoding);
        TOTPAuthenticatorImpl totpAuthenticator = new TOTPAuthenticatorImpl(gacb.build());
        return totpAuthenticator.createCredentials();
    }
}