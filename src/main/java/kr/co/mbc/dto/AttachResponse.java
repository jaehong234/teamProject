package kr.co.mbc.dto;

import kr.co.mbc.entity.BoardEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class AttachResponse {
	private Long id;
	private String filename;
	private BoardEntity boardEntity;
	
}
