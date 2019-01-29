package com.grokonez.jwtauthentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.grokonez.jwtauthentication.security.jwt.JwtAuthEntryPoint;
import com.grokonez.jwtauthentication.security.jwt.JwtAuthTokenFilter;
import com.grokonez.jwtauthentication.security.services.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
// 启用方法安全表达式
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	/**
	 * 提供用户的验证
	 */
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	/**
	 * 验证与登录请求由AuthenticationManager处理，如果发生错误，处理AuthenticationException由AuthenticationEntryPoint处理
	 */
	@Autowired
	private JwtAuthEntryPoint unauthorizedHandler;

	@Bean
	public JwtAuthTokenFilter authenticationJwtTokenFilter() {
		return new JwtAuthTokenFilter();
	}

	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder
				.userDetailsService(userDetailsService)
				.passwordEncoder(passwordEncoder());
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 资源权限的控制
	 * <p>{@link UsernamePasswordAuthenticationFilter} : 处理身份验证表单提交。
	 * 在Spring Security 3.0之前调用AuthenticationProcessingFilter。
	 * 登录表单必须向此过滤器提供两个参数：用户名和密码。
	 * 要使用的默认参数名称包含在静态字段SPRING_SECURITY_FORM_USERNAME_KEY和SPRING_SECURITY_FORM_PASSWORD_KEY中。
	 * 也可以通过设置usernameParameter和passwordParameter属性来更改参数名称。
	 * 默认情况下，此过滤器响应URL /login。
	 * <p>把JwtAuthTokenFilter增加到过滤器链中
	 *
	 * @param http
	 * @throws Exception
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors()
				.and()
				.csrf().disable()
				.authorizeRequests()
				.antMatchers("/api/auth/**").permitAll()
				.anyRequest().authenticated()
				.and()
				// 如果发生异常的处理
				.exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
				.and()
				// Spring Security永远不会创建HttpSession，就是不会在session中获取SecurityContext
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// 把JwtAuthTokenFilter增加到过滤器链中
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	}
}