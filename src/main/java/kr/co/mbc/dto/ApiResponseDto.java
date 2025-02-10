package kr.co.mbc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiResponseDto {

	private String statNm;
	private String statId;
	private String chgerId;
	private String chgerType;
	private String addr;
	private String addrDetail;
	private String location;
	private String useTime;
	private String lat;
	private String lng;
	private String busiId;
	private String bnm;
	private String busiNm;
	private String busiCall;
	private String stat;
	private String statUpdDt;
	private String lastTsdt;
	private String lastTedt;
	private String nowTsdt;
	private String powerType;
	private String output;
	private String method;
	private String zcode;
	private String zscode;
	private String kind;
	private String kindDetail;
	private String parkingFree;
	private String note;
	private String limitYn;
	private String limitDetail;
	private String delYn;
	private String delDetail;
	private String trafficYn;

}
