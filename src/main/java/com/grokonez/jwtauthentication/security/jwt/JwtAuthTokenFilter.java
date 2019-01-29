package com.grokonez.jwtauthentication.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.grokonez.jwtauthentication.security.services.UserDetailsServiceImpl;

/**
 * {@link OncePerRequestFilter}: 过滤基类，旨在保证在任何servlet容器上每次请求调度执行一次。
 * 它提供了带有HttpServletRequest和HttpServletResponse参数的
 * doFilterInternal（HttpServletRequest，HttpServletResponse，FilterChain）方法。
 */
public class JwtAuthTokenFilter extends OncePerRequestFilter {

	/**
	 *
	 */
	@Autowired
	private JwtProvider tokenProvider;

	/**
	 * 和数据库交互
	 */
	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

	/**
	 * 这里主要是为了验证令牌
	 *
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			// 1.获取令牌的密钥
			String jwt = getJwt(request);
			// 如果令牌不为null,并且令牌有效
			if (jwt != null && tokenProvider.validateJwtToken(jwt)) {
				// 2.从令牌中提取用户的信息
				String username = tokenProvider.getUserNameFromJwtToken(jwt);
				// 3.从令牌中获取的名字来查询数据库是不是有这个用户
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				/**
				 * UsernamePasswordAuthenticationToken：一种身份验证实现，旨在简单地显示用户名和密码。
				 * 应使用Object设置主体和凭证，该Object通过其Object.toString（）方法提供相应的属性。 最简单的这样的Object是String。
				 */
				UsernamePasswordAuthenticationToken authentication
						= new UsernamePasswordAuthenticationToken(userDetails,
						null,
						userDetails.getAuthorities() // 返回授予用户的权限，不能返回null。
				);

				/**
				 * {@link WebAuthenticationDetailsSource}：AuthenticationDetailsSource的实现，
				 * 它从HttpServletRequest对象构建详细信息对象，创建WebAuthenticationDetails。
				 *
				 * {@link AuthenticationDetailsSource}:为给定的Web请求提供Authentication.getDetails（）对象。
				 *
				 * {@link Authentication#getDetails()}: 有关身份验证请求的其他详细信息。 这些可能是IP地址，证书序列号等。
				 * 返回：有关身份验证请求的其他详细信息，如果未使用则为null
				 */
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// 4. 在SecutityCOntextHolder中存储身份验证对象
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			// 如果令牌无效或着为NULL，则使用AuthenticationEntryPoint来处理
		} catch (Exception e) {
			logger.error("Can NOT set user authentication -> Message: {}", e);
		}

		filterChain.doFilter(request, response);
	}

	/**
	 * @param request
	 * @return
	 */
	private String getJwt(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			return authHeader.replace("Bearer ", "");
		}

		return null;
	}
}
