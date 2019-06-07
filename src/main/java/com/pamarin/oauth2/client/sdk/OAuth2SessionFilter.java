/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.exception.AuthenticationException;
import com.pamarin.commons.exception.AuthorizationException;
import com.pamarin.commons.provider.HostUrlProvider;
import com.pamarin.commons.resolver.DefaultHttpCookieResolver;
import com.pamarin.commons.resolver.HttpCookieResolver;
import com.pamarin.commons.util.CookieSpecBuilder;
import com.pamarin.commons.util.QuerystringBuilder;
import java.io.IOException;
import static java.lang.String.format;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import static org.springframework.util.StringUtils.hasText;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 *
 * @author jitta
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OAuth2SessionFilter extends OncePerRequestFilter {

    private static final String CONTINUE_URL = "continue_url";

    private static final String STATE = "state";

    private static final String CODE = "code";

    private final OAuth2ClientOperations clientOperations;

    private final OAuth2AccessTokenResolver accessTokenResolver;

    private final OAuth2RefreshTokenResolver refreshTokenResolver;

    private final OAuth2TokenResolver accessTokenHeaderResolver;

    private final OAuth2LoginSession loginSession;

    private final OAuth2AccessTokenOperations accessTokenOperations;

    private final OAuth2AuthorizationState authorizationState;

    private final HttpCookieResolver returnPathCookieResolver;

    //default is false, if not define
    @Value("${oauth2.session-filter.disabled:#{false}}")
    private Boolean disabled;

    @Value("${oauth2.session-filter.authorize-success-url:#{null}}")
    private String authorizeSuccessUrl;

    private final String hostUrl;

    private final boolean isSecure;

    @Autowired
    public OAuth2SessionFilter(
            HostUrlProvider hostUrlProvider,
            OAuth2ClientOperations clientOperations,
            OAuth2AccessTokenResolver accessTokenResolver,
            OAuth2RefreshTokenResolver refreshTokenResolver
    ) {
        this.hostUrl = hostUrlProvider.provide();
        this.isSecure = this.hostUrl.startsWith("https://");
        this.clientOperations = clientOperations;
        this.accessTokenResolver = accessTokenResolver;
        this.refreshTokenResolver = refreshTokenResolver;
        this.accessTokenHeaderResolver = new RequestHeaderOAuth2TokenResolver();
        this.loginSession = new DefaultOAuth2LoginSession(clientOperations);
        this.authorizationState = new DefaultOAuth2AuthorizationState(hostUrlProvider);
        this.accessTokenOperations = createOAuth2AccessTokenOperations(
                hostUrlProvider,
                clientOperations,
                accessTokenResolver.getTokenName(),
                refreshTokenResolver.getTokenName()
        );
        this.returnPathCookieResolver = new DefaultHttpCookieResolver(CONTINUE_URL);
    }

    private DefaultOAuth2AccessTokenOperations createOAuth2AccessTokenOperations(
            HostUrlProvider hostUrlProvider,
            OAuth2ClientOperations clientOperations,
            String accessTokenName,
            String refreshTokenName
    ) {
        DefaultOAuth2AccessTokenOperations operations = new DefaultOAuth2AccessTokenOperations(hostUrlProvider, clientOperations);
        operations.setAccessTokenName(accessTokenName);
        operations.setRefreshTokenName(refreshTokenName);
        return operations;
    }

    public void setDisabled(Boolean disabled) {
        this.disabled = disabled;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        if (disabled == null) {
            return false;
        }
        return disabled;
    }

    private String getContinueUrl(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        return returnPathCookieResolver.resolve(httpReq);
    }

    private void saveContinueUrl(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        if (!hasText(authorizeSuccessUrl)) {
            authorizeSuccessUrl = hostUrl;
        }
        httpResp.addHeader("Set-Cookie",
                new CookieSpecBuilder(CONTINUE_URL, authorizeSuccessUrl)
                        .setMaxAge(60)
                        .setSecure(isSecure)
                        .setHttpOnly(true)
                        .build()
        );
    }

    private String getAuthorizationUrl(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        String state = authorizationState.create(httpReq, httpResp);
        return format("%s/oauth/authorize?%s",
                clientOperations.getAuthorizationServerHostUrl(),
                new QuerystringBuilder()
                        .addParameter("response_type", CODE)
                        .addParameter("client_id", clientOperations.getClientId())
                        .addParameter("redirect_uri", hostUrl + "/oauth/callback")
                        .addParameter("scope", clientOperations.getScope())
                        .addParameter(STATE, state)
                        .build()
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpReq, HttpServletResponse httpResp, FilterChain chain) throws ServletException, IOException {
        try {
            try {
                filter(httpReq, httpResp, chain);
            } catch (ReturnStatementException ex) {
                return;
            }
            chain.doFilter(httpReq, httpResp);
        } catch (AuthorizationException ex) {
            saveContinueUrl(httpReq, httpResp);
            httpResp.sendRedirect(getAuthorizationUrl(httpReq, httpResp));
        } catch (RequireRedirectException ex) {
            httpResp.sendRedirect(getContinueUrl(httpReq, httpResp));
        } catch (AuthenticationException ex) {
            httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }
    }

    private void filter(HttpServletRequest httpReq, HttpServletResponse httpResp, FilterChain chain) throws IOException, ServletException {
        try {
            sessionFilter(httpReq, httpResp, chain);
        } catch (IOException | ServletException ex) {
            loginSession.logout(httpReq);
            throw ex;
        }
    }

    private void sessionFilter(HttpServletRequest httpReq, HttpServletResponse httpResp, FilterChain chain) throws IOException, ServletException {
        String accessToken = accessTokenHeaderResolver.resolve(httpReq);
        if (hasText(accessToken)) {
            loginSession.login(accessToken, httpReq);
            return;
        }

        if (isAuthorizationCode(httpReq)) {
            getAccessTokenByAuthenticationCode(httpReq, httpResp);
            return;
        }

        if (isError(httpReq)) {
            convertAndThrowError(httpReq, httpResp);
            return;
        }

        getSession(httpReq, httpResp, chain);
    }

    private boolean isError(HttpServletRequest httpReq) {
        return hasText(httpReq.getParameter("error"))
                && hasText(httpReq.getParameter("error_status"));
    }

    private boolean isAuthorizationCode(HttpServletRequest httpReq) {
        return hasText(httpReq.getParameter(CODE))
                && hasText(httpReq.getParameter(STATE));
    }

    private void getAccessTokenByAuthenticationCode(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        authorizationState.verify(httpReq, httpResp);
        OAuth2AccessToken accessToken = accessTokenOperations.getAccessTokenByAuthenticationCode(
                httpReq.getParameter(CODE),
                httpReq,
                httpResp
        );

        if (accessToken != null) {
            throw new RequireRedirectException("Get accessToken by authorizationCode success.");
        }
    }

    private void convertAndThrowError(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        String state = httpReq.getParameter(STATE);
        if (hasText(state)) {
            authorizationState.verify(httpReq, httpResp);
        }
        throw OAuth2ErrorException.builder()
                .error(httpReq.getParameter("error"))
                .errorCode(httpReq.getParameter("error_code"))
                .errorDescription(httpReq.getParameter("error_description"))
                .errorStatus(Integer.valueOf(httpReq.getParameter("error_status")))
                .errorUri(httpReq.getParameter("error_uri"))
                .state(state)
                .build();
    }

    private void getSession(HttpServletRequest httpReq, HttpServletResponse httpResp, FilterChain chain) throws IOException, ServletException {
        try {
            String accessToken = accessTokenResolver.resolve(httpReq);
            loginSession.login(accessToken, httpReq);
        } catch (AuthenticationException ex) {
            try {
                String accessToken = refreshToken(httpReq, httpResp);
                clearResolverCache(httpReq);
                loginSession.login(accessToken, httpReq);
            } catch (AuthenticationException e) {
                chain.doFilter(httpReq, new UncommitErrorHttpServletResponse(httpResp));
                if (unauthorized(httpResp)) {
                    throw new AuthorizationException("Please authorize.", e);
                }
                throw new ReturnStatementException();
            }
        }
    }

    private boolean unauthorized(HttpServletResponse httpResp) {
        return httpResp.getStatus() == 401
                || httpResp.getStatus() == 403;
    }

    private String refreshToken(HttpServletRequest httpReq, HttpServletResponse httpResp) {
        String refreshToken = refreshTokenResolver.resolve(httpReq);
        if (!hasText(refreshToken)) {
            throw new AuthenticationException("Please login.");
        }
        return accessTokenOperations.getAccessTokenByRefreshToken(
                refreshToken,
                httpReq,
                httpResp
        ).getAccessToken();
    }

    private void clearResolverCache(HttpServletRequest httpReq) {
        accessTokenResolver.clearCache(httpReq);
        refreshTokenResolver.clearCache(httpReq);
    }

    @Slf4j
    public static class UncommitErrorHttpServletResponse extends HttpServletResponseWrapper {

        public UncommitErrorHttpServletResponse(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void sendError(int sc) throws IOException {
            super.setStatus(sc);
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            super.setStatus(sc);
            super.getOutputStream().print(msg);
        }

    }
}
