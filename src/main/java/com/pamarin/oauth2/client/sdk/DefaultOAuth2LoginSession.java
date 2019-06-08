/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pamarin.commons.exception.AuthenticationException;
import com.pamarin.commons.security.DefaultUserDetails;
import com.pamarin.commons.security.RSAKeyPairs;
import static com.pamarin.oauth2.client.sdk.OAuth2SdkConstant.OAUTH2_SECURITY_CONTEXT;
import static com.pamarin.oauth2.client.sdk.OAuth2SdkConstant.OAUTH2_SESSION;
import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import static org.springframework.util.StringUtils.hasText;
import org.springframework.web.client.HttpClientErrorException;

/**
 *
 * @author jitta
 */
@Slf4j
public class DefaultOAuth2LoginSession implements OAuth2LoginSession {

    private final OAuth2ClientOperations clientOperations;

    private final OAuth2AccessTokenResolver accessTokenResolver;

    private final OAuth2RefreshTokenResolver refreshTokenResolver;

    private final RSAKeyPairs rsaKeyPairs;

    public DefaultOAuth2LoginSession(
            OAuth2ClientOperations clientOperations,
            OAuth2AccessTokenResolver accessTokenResolver,
            OAuth2RefreshTokenResolver refreshTokenResolver,
            RSAKeyPairs rsaKeyPairs
    ) {
        this.clientOperations = clientOperations;
        this.accessTokenResolver = accessTokenResolver;
        this.refreshTokenResolver = refreshTokenResolver;
        this.rsaKeyPairs = rsaKeyPairs;
    }

    @Override
    public OAuth2Session login(String accessToken, HttpServletRequest httpReq) {
        if (!hasText(accessToken)) {
            logout(httpReq);
            throw new AuthenticationException("Please login.");
        }

        return doLogin(accessToken, httpReq);
    }

    private OAuth2Session doLogin(String accessToken, HttpServletRequest httpReq) {
        try {
            OAuth2Session session = getSession(accessToken);
            savePrincipal(session, httpReq);
            return session;
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                logout(httpReq);
                throw new AuthenticationException("Please login.");
            }
            throw ex;
        } catch (JWTVerificationException ex) {
            logout(httpReq);
            throw new AuthenticationException("Please login.");
        }
    }

    private OAuth2Session getSession(String accessToken) {
        if (accessToken.contains(".")) { //JWT is X-Session-ID
            DecodedJWT verify = JWT.require(Algorithm.RSA256(rsaKeyPairs.getPublicKey(), null))
                    .build()
                    .verify(accessToken);
            return OAuth2Session.builder()
                    .id(verify.getClaim("session.id").asString())
                    .issuedAt(verify.getClaim("session.issuedAt").asLong())
                    .expiresAt(verify.getClaim("session.expiresAt").asLong())
                    .user(
                            OAuth2Session.User.builder()
                                    .id(verify.getClaim("session.user.id").asString())
                                    .name(verify.getClaim("session.user.name").asString())
                                    .authorities(Arrays.asList(verify.getClaim("session.user.authorities").asArray(String.class)))
                                    .build()
                    )
                    .client(
                            OAuth2Session.Client.builder()
                                    .id(verify.getClaim("session.client.id").asString())
                                    .name(verify.getClaim("session.client.name").asString())
                                    .scopes(Arrays.asList(verify.getClaim("session.client.scopes").asArray(String.class)))
                                    .build()
                    )
                    .build();
        }

        return clientOperations.getSession(accessToken);
    }

    @Override
    public void logout(HttpServletRequest httpReq) {
        httpReq.setAttribute(OAUTH2_SESSION, null);
        httpReq.setAttribute(OAUTH2_SECURITY_CONTEXT, null);
        accessTokenResolver.clearCache(httpReq);
        refreshTokenResolver.clearCache(httpReq);
    }

    private void savePrincipal(OAuth2Session session, HttpServletRequest httpReq) {
        httpReq.setAttribute(OAUTH2_SESSION, session);
        httpReq.setAttribute(OAUTH2_SECURITY_CONTEXT, convertToSecurityContext(session.getUser()));
    }

    private SecurityContext convertToSecurityContext(OAuth2Session.User user) {
        DefaultUserDetails userDetails = DefaultUserDetails.builder()
                .username(user.getId())
                .password(null)
                .authorities(user.getAuthorities())
                .build();

        SecurityContext context = new SecurityContextImpl();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        ));
        return context;
    }
}
