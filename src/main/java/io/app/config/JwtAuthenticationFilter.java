package io.app.config;

import io.micrometer.common.lang.NonNull;
import io.micrometer.common.lang.NonNullFields;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	@Autowired
	private UserDetailsService userDetailsService;
	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {


		final String authHeader=request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		if (authHeader==null || !authHeader.startsWith("Bearer ")){
			filterChain.doFilter(request,response);
			return;
		}

		jwt=authHeader.substring(7);
		userEmail= jwtService.extractUsername(jwt);

		if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
			UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
			if (jwtService.isTokenValid(jwt,userDetails)){
				UsernamePasswordAuthenticationToken authToken=
						new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				authToken.setDetails(
						new WebAuthenticationDetailsSource().buildDetails(request)
				);
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request,response);
	}
}
