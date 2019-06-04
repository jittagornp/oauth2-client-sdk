/*
 * Copyright 2017-2019 Pamarin.com
 */
package com.pamarin.oauth2.client.sdk;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author jitta
 */
public interface OAuth2AuthorizationState {

    String create(HttpServletRequest httpReq, HttpServletResponse httpResp);

    void verify(HttpServletRequest httpReq, HttpServletResponse httpResp);

    void clear(HttpServletRequest httpReq, HttpServletResponse httpResp);

}
