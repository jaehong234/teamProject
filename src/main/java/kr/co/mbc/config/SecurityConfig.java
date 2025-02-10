package kr.co.mbc.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

import kr.co.mbc.entity.UserEntity;
import kr.co.mbc.service.CustomOAuth2UserService;
import kr.co.mbc.service.UserService;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final CustomOAuth2UserService customOAuth2UserService;
	
	@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		
//		http.csrf().disable();
		
		// 로그아웃 설정
		http.logout((auth) -> auth
				.logoutUrl("/auth/logout")
				.logoutSuccessUrl("/")
				.permitAll());
		
		// 일반로그인 설정
		http.formLogin((auth)-> auth
				.loginPage("/auth/loginForm")
				.loginProcessingUrl("/auth/login")
				.permitAll()
				.successHandler((request, response, authentication) -> {
	                // 로그인 후, 이전 페이지로 리다이렉트
	                String referer = (String) request.getSession().getAttribute("prevPage");
	                if (referer != null) {
	                    response.sendRedirect(referer); // 이전 페이지로 리다이렉트
	                } else {
	                    response.sendRedirect("/"); // 기본 페이지로 리다이렉트
	                }
				}));

		http.httpBasic((auth)-> auth.disable());
		
		// 네이버 로그인 설정
		http.oauth2Login((auth) -> auth
				.loginPage("/auth/oauth2login")
				.userInfoEndpoint((config) -> config.userService(customOAuth2UserService))
				.successHandler((request, response, authentication) -> {
	                // 로그인 후, 이전 페이지로 리다이렉트
	                String referer = (String) request.getSession().getAttribute("prevPage");
	                if (referer != null) {
	                    response.sendRedirect(referer); // 이전 페이지로 리다이렉트
	                } else {
	                    response.sendRedirect("/"); // 기본 페이지로 리다이렉트
	                }
				}));
		
		// 권한 설정
		http.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/cate/**" ,"/admin/**").hasRole("ADMIN")
				.requestMatchers("/user/**").hasAnyRole("ADMIN", "USER")
				.requestMatchers("/**").permitAll()
				);
		
		return http.build();
	}
}
