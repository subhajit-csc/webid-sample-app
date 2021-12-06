package com.gs.auth.oidc.webidsampleapp.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.gs.auth.oidc.webidsampleapp.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

public class RequestContextUserFilter extends GenericFilterBean {
    private static final Logger log = LoggerFactory.getLogger(RequestContextUserFilter.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    public  static final String USER_HEADER = "x-userinfo";

    @Override
    public void doFilter(
        ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain
    ) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        User user = findUser();
        if (user != null) {
            SecurityContextHolder.clearContext();
            Authentication authentication =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(req, servletResponse);
    }

    private User findUser() {
        String userInfoHeader;
        HttpServletRequest req;

        try {
            RequestAttributes reqAttr = RequestContextHolder.currentRequestAttributes();

            if (
                    reqAttr instanceof ServletRequestAttributes &&
                            (req = ((ServletRequestAttributes) reqAttr).getRequest()) != null &&
                            (userInfoHeader = req.getHeader(USER_HEADER)) != null
            ) {
                log.debug("Found user info from {} header with value: {}", USER_HEADER, userInfoHeader);
                // userinfo is base64 encoded
                userInfoHeader = new String(Base64.getDecoder().decode(userInfoHeader));
                log.debug("{} header base64 decoded: {}", USER_HEADER, userInfoHeader);
                User user =  mapper.readValue(userInfoHeader, User.class);
                req.setAttribute(User.class.getName(), user);
                return user;
            }
        } catch (IllegalStateException|IOException e) {
            log.error("Unable to resolve user from {} header", USER_HEADER, e);
        }

        log.debug("Did not find user from {} header.", USER_HEADER);
        return null;
    }
}
