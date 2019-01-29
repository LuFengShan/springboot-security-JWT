package com.grokonez.jwtauthentication.security.jwt;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * 认证（authe）入口点
 * {@link AuthenticationEntryPoint} : 由ExceptionTranslationFilter用于启动身份验证方案。
 */
@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

	private static final Logger logger = LoggerFactory.getLogger(JwtAuthEntryPoint.class);

	/**
	 * <b>commence</b> : 开始
	 * @param request
	 * @param response
	 * @param e
	 * @throws IOException
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException {
		logger.error("Unauthorized error. Message - {}", e.getMessage()); // 谁错误消息，提示未认证
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error -> Unauthorized");
	}
}