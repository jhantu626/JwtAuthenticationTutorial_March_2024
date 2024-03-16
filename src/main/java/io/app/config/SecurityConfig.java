package io.app.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig{
	@Autowired
	private JwtAuthenticationFilter JwtAuthenticationFilter;
	@Autowired
	private AuthenticationProvider authenticationProvider;
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(c->c.disable())
				.authorizeHttpRequests(auth->auth.requestMatchers("api/v1/auth/**")
						.permitAll()
						.anyRequest()
						.authenticated())
				.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider)
				.addFilterBefore(JwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}

}
