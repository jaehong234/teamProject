package kr.co.mbc.controller;

import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import kr.co.mbc.dto.UserForm;
import kr.co.mbc.entity.UserEntity;
import kr.co.mbc.service.UserService;
import kr.co.mbc.utils.FormatDateUtil;
import kr.co.mbc.utils.UploadFileUtils;
import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

	private final UserService userService;

	private static final String SERVICEPATH = "user";

	private final UploadFileUtils uploadFileUtils;
	
	private final FormatDateUtil formatDateUtil;
	
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
	private final AuthenticationManager authenticationManager;
	
	// 로그아웃 처리
	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		if(authentication != null) {
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}
		
		return "redirect:/";
	}

	// 로그인 처리
	@PostMapping("/login")
	public String login(String username, String password, HttpSession session) {
		
		UserEntity userEntity = userService.findByUsername(username);
		
		if (userEntity == null || !bCryptPasswordEncoder.matches(password, userEntity.getPassword())) {
	        // 사용자 없음 또는 비밀번호 불일치
	        return "auth/loginForm";
	    }
		
		String prevPage = (String) session.getAttribute("prevPage");
		if (prevPage != null) {
	        return "redirect:" + prevPage;
	    }

	    return "redirect:/"; // 기본 페이지로 리다이렉트
		
	}

	// 로그인 페이지
	@GetMapping("/loginForm")
	public String loginForm(@RequestHeader(value = "Referer", required = false) String referer, HttpSession session) {
	    // Referer가 존재하고 로그인 페이지가 아닐 경우 세션에 저장
	    if (referer != null && !referer.contains("/login")) {
	        session.setAttribute("prevPage", referer);
	    }
	    
	    return "auth/loginForm";
	}
	
	
//	@GetMapping("/loginForm")
//	public String loginForm(HttpServletRequest request, HttpSession session) {
//			
//		String referer = request.getHeader("Referer");
//		if (referer != null && !referer.contains("/login")) {
//	        session.setAttribute("prevPage", referer);
//	    }
//		
//		return "auth/loginForm";
//	}

	// 아이디 중복체크
	@PostMapping("/checkId")
	@ResponseBody
	public String checkId(@RequestParam Map<String, String> map) {
		
		String username = map.get("username");

		UserEntity dbEntity = userService.findByUsername(username);

		if (dbEntity == null) {
			return "ok";
		}

		return "no";
	}

	// 회원가입 처리
	@PostMapping("/join")
	public String insert(@Valid @ModelAttribute("userForm") UserForm userForm, BindingResult bindingResult,
			MultipartHttpServletRequest mRequest, HttpSession session) {

		if (bindingResult.hasErrors()) {
			return "auth/joinForm";
		}

		UserEntity userEntity = UserEntity.toUserEntity(userForm);

		MultipartFile multipartFile = mRequest.getFile("profileImage");

		if (!multipartFile.isEmpty()) {
			String fileName = uploadFileUtils.uploadFile(multipartFile, SERVICEPATH, userForm.getUsername());
			userEntity.setProfileImage(fileName);
		}

		userEntity.setCreateDate(formatDateUtil.getCurrentDate());
		userService.save(userEntity);

		// 회원가입 후 로그인 처리
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userForm.getUsername(), userForm.getPassword());

		Authentication authentication = authenticationManager.authenticate(token);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		// HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY -> Spring Security에서 인증 정보를 세션에 저장할 때 사용하는 키
		// 사용자 정보를 session에 저장해서 자동로그인 구현
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());

		return "redirect:/user/read/" + userForm.getUsername();
	}
	
//	@PostMapping("/join")
//	public String insert(@Valid @ModelAttribute("userForm") UserForm userForm, BindingResult bindingResult,
//			MultipartHttpServletRequest mRequest, HttpSession session) {
//
//		if (bindingResult.hasErrors()) {
//			return "auth/joinForm";
//		}
//
//		UserEntity userEntity = UserEntity.toUserEntity(userForm);
//
//		MultipartFile multipartFile = mRequest.getFile("profileImage");
//
//		if (!multipartFile.isEmpty()) {
//			String fileName = uploadFileUtils.uploadFile(multipartFile, SERVICEPATH, userForm.getUsername());
//			userEntity.setProfileImage(fileName);
//		}
//		
//		userEntity.setCreateDate(formatDateUtil.getCurrentDate());
//		userService.save(userEntity);
//		
//		return "redirect:/user/read/" + userForm.getUsername();
//	}

	// 회원가입 페이지
	@GetMapping("/joinForm")
	public String joinForm(UserForm userForm) {

		return "auth/joinForm";
	}

}
