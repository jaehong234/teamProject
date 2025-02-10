console.log("userService.js파일 불러옴.");

function makeImg(result) {
	let tag = `<img src="${result}" width="267" height="298">`;
	return tag;
}

$(function() {

	// 회원삭제 버튼 클릭 이벤트
	$("#user_read_deleteuser").click(function(event) {
		event.preventDefault();

		let isDelete = confirm("정말 탈퇴하시겠습니까?");

		if (isDelete) {
			let usernameValue = $(this).attr("href");
			let input = $("<input>").attr("name", "username").val(usernameValue);

			// CSRF 토큰 추가
			let csrfToken = $("#csrf_value").val();
			let csrfParameterName = $("#csrf_value").attr("name");
			let csrfInput = $("<input>").attr("type", "hidden").attr("name", csrfParameterName).val(csrfToken);


			let form = $("<form>").attr("method", "post").attr("action", "/user/delete");
			form.appendTo("body");
			form.append(input).append(csrfInput).submit();
		}
	});

	// 이미지 미리보기
	$("input[name='profileImage']").change(function(event) {
		let reader = new FileReader();
		let file = event.target.files[0];

		if (file) {
			reader.readAsDataURL(file);
			reader.onload = function(e) {
				let result = e.target.result;

				if (result.startsWith("data:image")) {
					// 기존의 makeImg() 함수 대신 직접 img 태그를 생성하여 class 유지
					let tag = `<img src="${result}" class="profile-img">`;
					$(".preview").html(tag);
				} else {
					alert("이미지 파일만 올리세요.");
					$("input[name='profileImage']").val('');
					$(".preview").empty();
				}
			};
		}
	});

	let username = $("input[name='username']");
	let password = $("input[name='password']");
	let password2 = $("input[name='password2']");
	let name = $("input[name='name']");

	let checkId = false;
	let confirmPassword = false;

	function isOk() {
		if (username.val() == '') {
			alert("아이디를 입력하세요.");
			return false;
		}

		if (password.val() == '') {
			alert("비밀번호를 입력하세요.");
			return false;
		}

		if (password2.val() == '') {
			alert("비밀번호를 확인하세요.");
			return false;
		}

		if (!confirmPassword) {
			alert("비밀번호가 일치하지 않습니다.");
			return false;
		}

		if (name.val() == '') {
			alert("이름을 입력하세요.");
			return false;
		}

		if (!checkId) {
			alert("중복검사 하세요.");
			return false;
		}

		return true;
	}


	// 회원등록 버튼 클릭 이벤트
	$("#auth_joinForm_submit").click(function() {
		if (isOk()) {
			$("form").submit();
		}
	});

	// 비밀번호 확인 input이벤트
	$("body").on("input", "input[type='password']", function() {
		confirmPassword = false;

		$("input[type='password']").next().removeAttr().text("");

		let passwordVal = $("input[name='password']").val();
		let password2Val = $("input[name='password2']").val();

		if (passwordVal == password2Val && passwordVal != '' && password2Val != '') {
			$("input[type='password']").next().attr("style", "color: blue").text("비밀번호 일치");
			confirmPassword = true;
		}
	});

	// input 이벤트
	$("body").on("input", "input[name='username']", function() {
		// 아이디 바꾸면 isOk false로, 중복체크버튼 다시 활성화
		$("#auth_joinForm_checkId").parent().next().removeAttr().text('');
		checkId = false;
		$("#auth_joinForm_checkId").prop("disabled", false);
	});

	// 중복체크 버튼 클릭 이벤트
	$("#auth_joinForm_checkId").click(function() {
		// name속성값이 username인 input태그
		let usernameValue = $("input[name='username']").val();
		// 토큰 값 가져오기
		let csrfToken = $("#csrfToken").val();

		// usernameValue가 비어있으면 알림창 띄우기
		if (usernameValue == '') {
			alert("아이디를 입력하세요.");
			return;
		}
		$.ajax({
			url: "/auth/checkId",
			type: "post",
			headers: {
				"X-CSRF-TOKEN": csrfToken  // CSRF 토큰을 헤더에 포함
			},
			data: {
				username: usernameValue
			},
			dataType: "text",
			success: function(result) {
				if (result == "ok") {
					// result가 ok일 때, span태그 style속성바꾸고, text로 '사용가능한 아이디'
					$("#auth_joinForm_checkId").parent().next().attr("style", "color: blue").text("사용가능한 아이디");
					checkId = true;
					$("#auth_joinForm_checkId").prop("disabled", true); // 중복체크 버튼 비활성화 시킴
				} else {
					$("#auth_joinForm_checkId").parent().next().attr("style", "color: red").text("이미사용중인 아이디");
				}
			}

		});
	});

});