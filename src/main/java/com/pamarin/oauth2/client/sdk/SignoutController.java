/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.provider.HostUrlProvider;
import com.pamarin.commons.util.QuerystringBuilder;
import java.io.IOException;
import static java.lang.String.format;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import static org.springframework.util.StringUtils.hasText;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.HttpClientErrorException;

/**
 *
 * @author jitta
 */
@Controller
public class SignoutController {

    private final HostUrlProvider hostUrlProvider;

    private final OAuth2ClientOperations clientOperations;

    private final OAuth2AccessTokenResolver accessTokenResolver;

    @Autowired
    public SignoutController(
            HostUrlProvider hostUrlProvider,
            OAuth2ClientOperations clientOperations,
            OAuth2AccessTokenResolver accessTokenResolver
    ) {
        this.hostUrlProvider = hostUrlProvider;
        this.clientOperations = clientOperations;
        this.accessTokenResolver = accessTokenResolver;
    }

    private String getSignoutUrl() {
        return format("%s/oauth/signout?%s",
                clientOperations.getAuthorizationServerHostUrl(),
                new QuerystringBuilder()
                        .addParameter("client_id", clientOperations.getClientId())
                        .addParameter("redirect_uri", hostUrlProvider.provide())
                        .build()
        );
    }

    private void signoutFromBackendService(HttpServletRequest httpReq) {
        String accessToken = accessTokenResolver.resolve(httpReq);
        if (!hasText(accessToken)) {
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
        }
        clientOperations.post(
                format("%s/oauth/signout", clientOperations.getAuthorizationServerHostUrlForBackend() ),
                null,
                String.class,
                accessToken
        );
    }

    @GetMapping("/oauth/signout")
    public void signout(HttpServletRequest httpReq, HttpServletResponse httpResp) throws IOException {
        try {
            signoutFromBackendService(httpReq);
            httpResp.sendRedirect(hostUrlProvider.provide());
        } catch (HttpClientErrorException ex) {
            if (ex.getStatusCode() != HttpStatus.UNAUTHORIZED) {
                throw ex;
            }

            httpResp.sendRedirect(getSignoutUrl());
        }
    }

}
