<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>게시글 입력 화면</title>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js" type="text/javascript"></script>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
    <style>
    
    
*, *::before, *::after {
    box-sizing: inherit;
}



form div {
    margin-bottom: 20px;
}

form label {
    font-size: 1.1em;
    color: #555;
    font-weight: 500;
    display: block;
    margin-bottom: 8px;
}



textarea {
    resize: none; /* 텍스트 영역 크기 조절 방지 */
    height: 150px;
}

button {
    width: 100%;
    padding: 12px;
    background: linear-gradient(90deg, #FF9F00, #FFA726); /* 감귤 그라데이션 */
    border: none;
    border-radius: 8px;
    color: white;
    font-weight: bold;
    font-size: 1.2em;
    transition: all 0.3s ease;
    cursor: pointer;
}

button:hover {
    background: linear-gradient(90deg, #FFB74D, #FFCC80);
    transform: t


    </style>
    
    <link href="/css/boardStyle.css" rel="stylesheet">
</head>
<body>
<%@ include file="../part/part_header.jsp" %>

	<div class="container" id="board_insert_css">
		<div>
			<h3>게시글 입력</h3>
		</div>
		<div>
			<form:form modelAttribute="boardForm" id="boardForm" action="/board/${cid}/insert" method="post" enctype="multipart/form-data">
				<form:errors path="*" cssClass="errorblock" element="div"></form:errors>

				<div>
					<label>제목</label> <input name="title">
				</div>
				
				<!-- 카테고리 드롭다운 추가 -->
	            <div>
	                <label>카테고리</label>
	                <select name="category" id="cate_select" class="form-control">
	                    <option value="" disabled selected>카테고리를 선택하세요</option>
	                    <c:forEach var="cateList" items="${cateList}">
	                        <c:if test="${cateList.cid != 'notice' || principal.role == 'ROLE_ADMIN'}">
               					 <option value="${cateList.cid}">${cateList.cname}</option>
            				</c:if>
	                    </c:forEach>
	                </select>
	            </div>
				
				<div>
					<label>작성자</label> <input id="board_insert_writer" name="writer" value="${principal.username}"  readonly="readonly">
				</div>
				<div>
					<label>내용</label>
					<textarea rows="5" name="content"></textarea>
				</div>
				<div>
					<div class="preview"
						style="width: 100px; height: 100px; border: 1px solid;"></div>
					<input type="file" name="myfile">
				</div>
				<div>
					<button type="button" id="board_insert_btn_submit">글 입력 완료</button>
				</div>
				
				<c:if test="${category == 'list'}">
					<a href="/board/list" class="btn btn-success">목록</a>
				</c:if>
				
				<c:if test="${category != 'list'}">
					<a href="/board/${category}/list" class="btn btn-success">목록</a>
				</c:if>
				
			</form:form>
		</div>
	</div>
	
	<script type="text/javascript" src="/js/boardService.js"></script>
	<script type="text/javascript">
	
	// 카테고리 선택에 따라 form 태그 action이 변경됨
	$("#cate_select").change(function(){
		let cate = $(this).val();
		$("#boardForm").attr("action", "/board/"+cate+"/insert");
	});
	
	// 카테고리 선택하지 않으면 alert창 뜨게 함.
	$("#boardForm").submit(function () {
        let category = $("#cate_select").val();
        
        if (!category) {
            alert("카테고리를 선택하세요!");
            return false;  // 제출 막기
        }
    });
	
	$("#board_insert_btn_submit").click(function(){
		
		let title = $("input[name='title']").val();
		if(title != ''){
			$("#boardForm").submit();
		} else {
			alert("제목입력하세요");
		}
		
	});
	
// 	// principal.username 값을 가져오기
//     let username = "${principal.username}";

//     // 만약 username이 'naver'로 시작하면 '___mbc___' 뒤 5글자만 추출
//     if (username.startsWith("naver")) {
//         let suffix = username.split("___mbc___")[1].substring(0, 5);
//         document.getElementById("board_insert_writer").value = suffix;
//     }
	
	</script>
</body>
</html>