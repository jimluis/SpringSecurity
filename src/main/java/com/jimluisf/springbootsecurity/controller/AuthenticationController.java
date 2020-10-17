package com.jimluisf.springbootsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.jimluisf.springbootsecurity.config.CustomUserDetailsService;
import com.jimluisf.springbootsecurity.config.JWTUtils;
import com.jimluisf.springbootsecurity.model.AuthenticationRequest;
import com.jimluisf.springbootsecurity.model.AuthenticationResponse;

@RestController
public class AuthenticationController 
{
	@Autowired
	private AuthenticationManager authenticationManager; 
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	JWTUtils jwtUtil;
	
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest ) throws Exception 
	{
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword()));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLE", e);
		}catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
		UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUserName());
		String token = jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(token));
		
		
	}
}
