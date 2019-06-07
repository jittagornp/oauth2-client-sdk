/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.exception.AuthenticationException;
import com.pamarin.commons.provider.DefaultHttpServletRequestProvider;
import com.pamarin.commons.provider.HttpServletRequestProvider;
import com.pamarin.commons.resolver.DefaultHttpClientIPAddressResolver;
import com.pamarin.commons.resolver.HttpClientIPAddressResolver;
import com.pamarin.commons.util.Base64Utils;
import com.pamarin.commons.util.MultiValueMapBuilder;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import static org.springframework.util.StringUtils.hasText;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.cloud.sleuth.Span;
import org.springframework.cloud.sleuth.Tracer;

/**
 *
 * @author jitta
 */
@Slf4j
public class DefaultOAuth2ClientOperations implements OAuth2ClientOperations {

    private static final String TRACE = "org.springframework.cloud.sleuth.instrument.web.TraceFilter.TRACE";

    private final String clientId;

    private final String basicAuthorization;

    private final String authorizationServerHostUrl;

    private String authorizationServerHostUrlForBackend;

    private final String scope;

    private final RestTemplate restTemplate;

    private final HttpServletRequestProvider httpServletRequestProvider;

    private final HttpClientIPAddressResolver httpClientIPAddressResolver;

    private final Tracer tracer;

    public DefaultOAuth2ClientOperations(String clientId, String clientSecret, String authorizationServerHostUrl, String scope, Tracer tracer) {
        this.scope = scope;
        this.tracer = tracer;
        this.clientId = clientId;
        this.restTemplate = new RestTemplate();
        this.basicAuthorization = Base64Utils.encode(clientId + ":" + clientSecret);
        this.authorizationServerHostUrl = authorizationServerHostUrl;
        this.httpServletRequestProvider = new DefaultHttpServletRequestProvider();
        this.httpClientIPAddressResolver = new DefaultHttpClientIPAddressResolver();
    }

    private void saveRequestAttribute(String name, Object value) {
        HttpServletRequest httpReq = httpServletRequestProvider.provide();
        if (httpReq != null) {
            httpReq.setAttribute(name, value);
        }
    }

    private MultiValueMapBuilder addDefaultHeaders(MultiValueMapBuilder<String, String> builder) {
        HttpServletRequest httpReq = httpServletRequestProvider.provide();
        if (httpReq != null) {
            String ipAddress = httpClientIPAddressResolver.resolve(httpReq);
            builder.add("X-Forwarded-For", ipAddress)
                    .add("REMOTE_ADDR", ipAddress)
                    .add("X-B3-TraceId", getTraceId(httpReq))
                    .add("X-Request-ID", httpReq.getHeader("X-Request-ID"))
                    .add("User-Agent", httpReq.getHeader("User-Agent"))
                    .add("Referer", httpReq.getHeader("Referer"))
                    .add("Host", httpReq.getHeader("Host"));
        }
        return builder;
    }

    private String getTraceId(HttpServletRequest httpReq) {
        Span span = (Span) httpReq.getAttribute(TRACE);
        if (span == null) {
            return null;
        }
        return span.traceIdString();
    }

    private MultiValueMap<String, String> buildAccessTokenHeaders() {
        return addDefaultHeaders(MultiValueMapBuilder.newLinkedMultiValueMap()
                .add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .add("Authorization", "Basic " + basicAuthorization))
                .build();
    }

    private MultiValueMap<String, String> buildHeaders(String accessToken) {
        return addDefaultHeaders(MultiValueMapBuilder.newLinkedMultiValueMap()
                .add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .add("Authorization", "Bearer " + accessToken))
                .build();
    }

    private MultiValueMap<String, String> buildAuthorizationCodeBody(String authorizationCode) {
        return MultiValueMapBuilder.newLinkedMultiValueMap()
                .add("grant_type", "authorization_code")
                .add("redirect_uri", "")
                .add("code", authorizationCode)
                .build();
    }

    private MultiValueMap<String, String> buildRefreshTokenBody(String refreshToken) {
        return MultiValueMapBuilder.newLinkedMultiValueMap()
                .add("grant_type", "refresh_token")
                .add("redirect_uri", "")
                .add("refresh_token", refreshToken)
                .build();
    }

    @Override
    public OAuth2AccessToken getAccessTokenByAuthorizationCode(String authorizationCode) {
        try {
            return restTemplate.postForEntity(getAuthorizationServerHostUrlForBackend() + "/oauth/token",
                    new HttpEntity<>(buildAuthorizationCodeBody(authorizationCode), buildAccessTokenHeaders()),
                    OAuth2AccessToken.class
            ).getBody();
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new AuthenticationException("/oauth/token by code", ex);
            }
            throw ex;
        }
    }

    @Override
    public OAuth2AccessToken getAccessTokenByAuthorizationCode(String authorizationCode, boolean createNewSpan) {
        if (!createNewSpan) {
            return getAccessTokenByAuthorizationCode(authorizationCode);
        }

        Span newSpan = this.tracer.createSpan("code:/oauth/token");
        try {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_SEND);
            saveRequestAttribute(TRACE, newSpan);
            return getAccessTokenByAuthorizationCode(authorizationCode);
        } finally {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_RECV);
            this.tracer.close(newSpan);
        }
    }

    @Override
    public OAuth2AccessToken getAccessTokenByRefreshToken(String refreshToken) {
        try {
            return restTemplate.postForEntity(getAuthorizationServerHostUrlForBackend() + "/oauth/token",
                    new HttpEntity<>(buildRefreshTokenBody(refreshToken), buildAccessTokenHeaders()),
                    OAuth2AccessToken.class
            ).getBody();
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new AuthenticationException("/oauth/token by refresh token", ex);
            }
            throw ex;
        }
    }

    @Override
    public OAuth2AccessToken getAccessTokenByRefreshToken(String refreshToken, boolean createNewSpan) {
        if (!createNewSpan) {
            return getAccessTokenByRefreshToken(refreshToken);
        }

        Span newSpan = this.tracer.createSpan("refresh:/oauth/token");
        try {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_SEND);
            saveRequestAttribute(TRACE, newSpan);
            return getAccessTokenByRefreshToken(refreshToken);
        } finally {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_RECV);
            this.tracer.close(newSpan);
        }
    }

    @Override
    public OAuth2Session getSession(String accessToken) {
        try {
            return restTemplate.postForEntity(getAuthorizationServerHostUrlForBackend() + "/oauth/session",
                    new HttpEntity<>(null, buildHeaders(accessToken)),
                    OAuth2Session.class
            ).getBody();
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new AuthenticationException("/oauth/session", ex);
            }
            throw ex;
        }
    }

    @Override
    public OAuth2Session getSession(String accessToken, boolean createNewSpan) {
        if (!createNewSpan) {
            return getSession(accessToken);
        }

        Span newSpan = this.tracer.createSpan("/oauth/session");
        try {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_SEND);
            saveRequestAttribute(TRACE, newSpan);
            return getSession(accessToken);
        } finally {
            newSpan.logEvent(org.springframework.cloud.sleuth.Span.CLIENT_RECV);
            this.tracer.close(newSpan);
        }
    }

    @Override
    public <T> T get(String url, Class<T> responseType, String accessToken) {
        try {
            return restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(null, buildHeaders(accessToken)),
                    responseType
            ).getBody();
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new AuthenticationException("url : " + url, ex);
            }
            throw ex;
        }
    }

    @Override
    public <T> T post(String url, Object request, Class<T> responseType, String accessToken) {
        try {
            return restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(request, buildHeaders(accessToken)),
                    responseType
            ).getBody();
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new AuthenticationException("url : " + url, ex);
            }
            throw ex;
        }
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public String getAuthorizationServerHostUrl() {
        return authorizationServerHostUrl;
    }

    @Override
    public String getAuthorizationServerHostUrlForBackend() {
        if (hasText(authorizationServerHostUrlForBackend)) {
            return authorizationServerHostUrlForBackend;
        }
        return authorizationServerHostUrl;
    }

    public void setAuthorizationServerHostUrlForBackend(String authorizationServerHostUrlForBackend) {
        this.authorizationServerHostUrlForBackend = authorizationServerHostUrlForBackend;
    }

    @Override
    public String getScope() {
        return scope;
    }

}
