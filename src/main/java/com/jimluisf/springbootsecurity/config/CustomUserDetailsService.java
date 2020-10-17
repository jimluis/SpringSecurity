package com.jimluisf.springbootsecurity.config;

import java.util.Arrays;
import java.util.List;


import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService
{

	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException 
	{
		List<SimpleGrantedAuthority> roles = null;
		
		if(userName.equals("admin"))
		{
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
			return new User("admin", "$2a$10$ySM1Cqeqt9CDF688Eij9DOQOAH6Ozk3sOFRTLjRX3yQi3.8Vuo.gq", roles);
		}
		
		else if(userName.equals("user"))
		{
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
			return new User("user", "$2a$10$pvA2u2XCkdcF/O3AVM1f1.QJ5/NMGUqEreDEgbL8P1SIUzVwDnmrO", roles);
		}
		
		throw new UsernameNotFoundException("User not found with userName: "+userName);
		
	}

}