/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.exception.AuthenticationException;
import com.pamarin.commons.exception.AuthorizationException;
import com.pamarin.commons.provider.HostUrlProvider;
import com.pamarin.commons.util.CookieSpecBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.springframework.util.StringUtils.hasText;

/**
 *
 * @author jitta
 */
public class DefaultOAuth2AccessTokenOperations implements OAuth2AccessTokenOperations {

    private static final String ERROR_MESSAGE = "Please authorize.";

    private static final int ONE_DAY_SECONDS = 60 * 60 * 24;

    private static final int FOURTEEN_DAYS_SECONDS = ONE_DAY_SECONDS * 14;

    private final HostUrlProvider hostUrlProvider;

    private final OAuth2ClientOperations clientOperations;

    private String accessTokenName = "access_token";

    private String refreshTokenName = "refresh_token";

    public DefaultOAuth2AccessTokenOperations(HostUrlProvider hostUrlProvider, OAuth2ClientOperations clientOperations) {
        this.hostUrlProvider = hostUrlProvider;
        this.clientOperations = clientOperations;
    }

    @Override
    public OAuth2AccessToken getAccessTokenByAuthenticationCode(String code, HttpServletRequest httpReq, HttpServletResponse httpResp) {
        if (!hasText(code)) {
            throw new AuthorizationException(ERROR_MESSAGE);
        }

        return getTokenByCode(code, httpReq, httpResp);
    }

    private OAuth2AccessToken getTokenByCode(String code, HttpServletRequest httpReq, HttpServletResponse httpResp) {
        try {
            OAuth2AccessToken accessToken = clientOperations.getAccessTokenByAuthorizationCode(code);
            storeToken(accessToken, httpReq, httpResp);
            return accessToken;
        } catch (AuthenticationException ex) {
            throw new AuthorizationException(ERROR_MESSAGE, ex);
        }
    }

    @Override
    public OAuth2AccessToken getAccessTokenByRefreshToken(String refreshToken, HttpServletRequest httpReq, HttpServletResponse httpResp) {
        if (!hasText(refreshToken)) {
            throw new AuthorizationException(ERROR_MESSAGE);
        }

        return getTokenByRefreshToken(refreshToken, httpReq, httpResp);
    }

    private OAuth2AccessToken getTokenByRefreshToken(String refreshToken, HttpServletRequest httpReq, HttpServletResponse httpResp) {
        try {
            OAuth2AccessToken accessToken = clientOperations.getAccessTokenByRefreshToken(refreshToken);
            storeToken(accessToken, httpReq, httpResp);
            return accessToken;
        } catch (AuthenticationException ex) {
            throw new AuthorizationException(ERROR_MESSAGE, ex);
        }
    }

    public void setAccessTokenName(String accessTokenName) {
        this.accessTokenName = accessTokenName;
    }

    public void setRefreshTokenName(String refreshTokenName) {
        this.refreshTokenName = refreshTokenName;
    }

    private void storeToken(OAuth2AccessToken accessToken, HttpServletRequest httpReq, HttpServletResponse httpResp) {
        //cookie
        httpResp.addHeader("Set-Cookie", buildCookie(
                accessTokenName,
                accessToken.getAccessToken(),
                ONE_DAY_SECONDS
        ));

        httpResp.addHeader("Set-Cookie", buildCookie(
                refreshTokenName,
                accessToken.getRefreshToken(),
                FOURTEEN_DAYS_SECONDS
        ));

        //request attribute
        httpReq.setAttribute(accessTokenName, accessToken.getAccessToken());
        httpReq.setAttribute(refreshTokenName, accessToken.getRefreshToken());
    }

    private String buildCookie(String name, String value, int maxAge) {
        return new CookieSpecBuilder(name, value)
                .setHttpOnly(Boolean.TRUE)
                .setPath("/")
                .setSecure(hostUrlProvider.provide().startsWith("https://"))
                .setMaxAge(maxAge)
                .build();
    }

}
