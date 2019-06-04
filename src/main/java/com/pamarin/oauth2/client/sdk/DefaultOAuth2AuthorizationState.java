/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.provider.HostUrlProvider;
import com.pamarin.commons.resolver.DefaultHttpCookieResolver;
import com.pamarin.commons.resolver.HttpCookieResolver;
import com.pamarin.commons.util.Base64Utils;
import com.pamarin.commons.util.CookieSpecBuilder;
import java.security.SecureRandom;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import static org.springframework.util.StringUtils.hasText;

/**
 *
 * @author jitta
 */
public class DefaultOAuth2AuthorizationState implements OAuth2AuthorizationState {

    private static final int AUTHORIZATION_STATE_COOKIE_EXPIRES = 60 * 30; //30 minutes

    private static final String AUTHORIZATION_STATE_COOKIE = "authorize_state";

    private static final int STATE_SIZE = 11;

    private final SecureRandom secureRandom = new SecureRandom();

    private final HttpCookieResolver cookieResolver = new DefaultHttpCookieResolver(AUTHORIZATION_STATE_COOKIE);

    private final boolean isSecure;

    @Autowired
    public DefaultOAuth2AuthorizationState(HostUrlProvider hostUrlProvider) {
        this.isSecure = hostUrlProvider.provide().startsWith("https://");
    }

    @Override
    public String create(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        String state = randomState();
        httpResp.addHeader("Set-Cookie", buildCookie(state, AUTHORIZATION_STATE_COOKIE_EXPIRES));
        return state;
    }

    @Override
    public void verify(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        String state = httpReq.getParameter("state");
        if (!hasText(state)) {
            return;
        }
        String cookieState = cookieResolver.resolve(httpReq);
        if (!Objects.equals(state, cookieState)) {
            throw new InvalidAuthorizationStateException(state);
        }
    }

    private String randomState() {
        byte[] bytes = new byte[STATE_SIZE];
        secureRandom.nextBytes(bytes);
        return Base64Utils.encode(bytes);
    }

    @Override
    public void clear(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        httpResp.addHeader("Set-Cookie", buildCookie("", 1));
    }

    private String buildCookie(String state, int maxAge) {
        return new CookieSpecBuilder(AUTHORIZATION_STATE_COOKIE, state)
                .setHttpOnly(Boolean.TRUE)
                .setPath("/")
                .setSecure(isSecure)
                .setMaxAge(maxAge)
                .build();
    }

}
