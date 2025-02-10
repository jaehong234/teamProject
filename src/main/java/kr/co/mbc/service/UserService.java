package kr.co.mbc.service;

import java.util.List;
import java.util.Optional;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import kr.co.mbc.dto.Criteria;
import kr.co.mbc.entity.UserEntity;
import kr.co.mbc.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;

	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public void update(UserEntity userEntity) {
		userRepository.save(userEntity);
	}

	public void save(UserEntity userEntity) {
		String encodingPass = bCryptPasswordEncoder.encode(userEntity.getPassword());
		userEntity.setPassword(encodingPass);
		userRepository.save(userEntity);
	}

	public UserEntity findByUsername(String username) {
		return userRepository.findByUsername(username);
	}

	@Transactional
	public void deleteByUsername(String username) {
		userRepository.deleteByUsername(username);
	}

	public List<UserEntity> findMembers(Criteria criteria) {

		return userRepository.findMembers(criteria);
	}

	public UserEntity findById(Long i) {
		Optional<UserEntity> opt = userRepository.findById(i);

		if (opt.isPresent()) {
			UserEntity userEntity = opt.get();
			return userEntity;
		}
		return null;
	}

	public Long getTotalCount(Criteria criteria) {
		return userRepository.getTotalCount(criteria);
	}

	public UserEntity findByUsernameAndPassword(String username, String encodePass) {
		return userRepository.findByUsernameAndPassword(username, encodePass);
	}

}
