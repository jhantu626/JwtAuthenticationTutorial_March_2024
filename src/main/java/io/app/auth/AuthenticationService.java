package io.app.auth;

import io.app.config.JwtService;
import io.app.model.Role;
import io.app.model.User;
import io.app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JwtService jwtService;
	@Autowired
	private AuthenticationManager authenticationManager;
	public AuthenticationResponse register(RegisterRequest request) {
		var user= User.builder()
				.firstName(request.getFirstName())
				.lastName(request.getLastName())
				.email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword()))
				.role(Role.USER).build();
		userRepository.save(user);
		var jwtToken=jwtService.generateToken(user);
		return AuthenticationResponse.builder()
				.token(jwtToken).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getEmail(),
						request.getPassword()
				)
		);
		var user=userRepository.findByEmail(request.getEmail())
				.orElseThrow(()->new UsernameNotFoundException("Not Found"));
		var token=jwtService.generateToken(user);
		return AuthenticationResponse.builder()
				.token(token).build();
	}
}
