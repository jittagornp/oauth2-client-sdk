/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import com.pamarin.commons.util.CookieSpecBuilder;
import java.time.LocalDateTime;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author jitta
 */
public class CleanSessionCookieUtils {

    private CleanSessionCookieUtils() {

    }

    public static void clean(HttpServletResponse httpResp) {
        httpResp.addHeader("Set-Cookie", expiredCookie("access_token"));
        httpResp.addHeader("Set-Cookie", expiredCookie("refresh_token"));
        httpResp.addHeader("Set-Cookie", expiredCookie("authorize_state"));
        httpResp.addHeader("Set-Cookie", expiredCookie("continue_url"));
    }

    private static String expiredCookie(String cookieName) {
        return new CookieSpecBuilder(cookieName, "")
                .setExpires(LocalDateTime.now().minusYears(1000))
                .setHttpOnly(true)
                .build();
    }
}
