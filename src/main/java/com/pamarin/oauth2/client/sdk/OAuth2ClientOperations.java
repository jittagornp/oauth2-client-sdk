/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

/**
 *
 * @author jitta
 */
public interface OAuth2ClientOperations {

    String getClientId();

    String getAuthorizationServerHostUrl();
    
    String getAuthorizationServerHostUrlForBackend();

    String getScope();

    OAuth2AccessToken getAccessTokenByAuthorizationCode(String authorizationCode);
    
    OAuth2AccessToken getAccessTokenByAuthorizationCode(String authorizationCode, boolean createNewSpan);

    OAuth2AccessToken getAccessTokenByRefreshToken(String refreshToken);
    
    OAuth2AccessToken getAccessTokenByRefreshToken(String refreshToken, boolean createNewSpan);

    OAuth2Session getSession(String accessToken);
    
    OAuth2Session getSession(String accessToken, boolean createNewSpan);

    <T> T get(String url, Class<T> responseType, String accessToken);

    <T> T post(String url, Object request, Class<T> responseType, String accessToken);

}
