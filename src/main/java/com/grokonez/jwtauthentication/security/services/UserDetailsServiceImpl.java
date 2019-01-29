package com.grokonez.jwtauthentication.security.services;

import com.grokonez.jwtauthentication.model.User;
import com.grokonez.jwtauthentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link UserDetailsService} ：加载用户特定数据的核心接口。它在整个框架中用作用户DAO，并且是DaoAuthenticationProvider使用的策略。
 * 该接口只需要一个只读方法，这简化了对新数据访问策略的支持。
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	UserRepository userRepository;

	/**
	 * 根据用户的名字来查询用户信息，如果用户不用在就抛出用户不存在的异常
	 *
	 * @param username
	 * @return
	 * @throws UsernameNotFoundException
	 */
	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 根据用户的名字来查询用户信息，如果用户不用在就抛出异常
		User user = userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with -> username or email : " + username)
				);
		return UserPrinciple.build(user);
	}
}