package io.app.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

	private static final String SECRET_KEY="3zEYxnei5RPxxCVdg57NTtMbdXk6bnFnOKiw1taxdUC06fRdQybzqGQkV1Yvc8DROAqNOyTQDwKse09PX+gQag==";

	public String extractUsername(String token) {
		return extractClaim(token,Claims::getSubject);
	}

	public boolean isTokenValid(String token,UserDetails userDetails){
		final String username=extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}
	public boolean isTokenExpired(String token){
		return extractExpiration(token).before(new Date());
	}
	public Date extractExpiration(String token){
		return extractClaim(token,Claims::getExpiration);
	}


	public <T> T extractClaim(String token, Function<Claims,T> resolver){
		final Claims claims=extractAllClaims(token);
		return resolver.apply(claims);
	}

	private Claims extractAllClaims(String token){
		return Jwts.parserBuilder()
				.setSigningKey(getSignInKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	public String generateToken(UserDetails userDetails){
		return generateToken(new HashMap<>(),userDetails);
	}
	public String generateToken(
			Map<String,Object> extraClaims,
			UserDetails userDetails
	){
		return Jwts.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+ 1000*60*24))
				.signWith(getSignInKey(), SignatureAlgorithm.HS256)
				.compact();
	}

	public SecretKey getSignInKey(){
		byte[] key= Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(key);
	}

}



