/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.provider.HostUrlProvider;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import static org.springframework.util.StringUtils.hasText;
import org.springframework.web.bind.annotation.GetMapping;

/**
 *
 * @author jitta
 */
@Controller
public class OAuth2CallbackController {

    @Autowired
    private HostUrlProvider hostUrlProvider;

    @Value("${oauth2.session-filter.authorize-success-url:#{null}}")
    private String authorizeSuccessUrl;

    @GetMapping("/oauth/callback")
    public void callback(HttpServletRequest httpReq, HttpServletResponse httpResp) throws IOException {
        httpResp.sendRedirect(getAuthorizeSuccessUrl());
    }

    private String getAuthorizeSuccessUrl() {
        if (!hasText(authorizeSuccessUrl)) {
            return hostUrlProvider.provide();
        }
        return authorizeSuccessUrl;
    }
}
