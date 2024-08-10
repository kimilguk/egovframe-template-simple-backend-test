package egovframework.com.sns;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

import egovframework.com.cmm.EgovMessageSource;
import egovframework.com.cmm.LoginVO;
import egovframework.com.jwt.EgovJwtTokenUtil;
import egovframework.let.uat.uia.service.EgovLoginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
/**
 * Sns 로그인을 처리하는 컨트롤러 클래스
 * @기술참조(네이버API명세) : https://developers.naver.com/docs/login/api/api.md
 * @version 1.0
 *
 * <pre>
 * << 개정이력(Modification Information) >>
 *
 *  수정일      수정자      수정내용
 *  -------            --------        ---------------------------
 *  2024.08.15  김일국     최초 생성
 *
 *  </pre>
 */
@Slf4j
@RestController
@Tag(name="SnsLoginApiController",description = "Sns 로그인 관련")
public class SnsLoginApiController {
	
	/** EgovLoginService */
	@Resource(name = "loginService")
	private EgovLoginService loginService;
	/** EgovMessageSource */
	@Resource(name = "egovMessageSource")
	EgovMessageSource egovMessageSource;
	/** JWT */
	@Autowired
    private EgovJwtTokenUtil jwtTokenUtil;
	
	@Operation(
			summary = "네이버API 로그인",
			description = "네이버API 로그인 처리",
			tags = {"SnsLoginApiController"}
	)
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "로그인 성공"),
			@ApiResponse(responseCode = "300", description = "로그인 실패")
	})
	@GetMapping("/login/naver")
    public void getNaverAuthUrl(HttpServletResponse response) throws IOException {
		String clientId = "osgm3bqYygYV49c1QPWl";//네이버 애플리케이션 클라이언트 아이디값";
		String redirectURI = URLEncoder.encode("http://127.0.0.1:8080/login/callback", "UTF-8");
	    SecureRandom random = new SecureRandom();
	    String state = new BigInteger(130, random).toString();
	    String apiURL = "https://nid.naver.com/oauth2.0/authorize?response_type=code";
	    apiURL += "&client_id=" + clientId;
	    apiURL += "&redirect_uri=" + redirectURI;
	    apiURL += "&state=" + state;
		response.sendRedirect(apiURL);
	}
	@Operation(
			summary = "네이버API 로그인 콜백",
			description = "네이버API 로그인 콜백처리",
			tags = {"SnsLoginApiController"}
	)
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "로그인 성공"),
			@ApiResponse(responseCode = "300", description = "로그인 실패")
	})
	@GetMapping("/login/callback")
    public HashMap<String, Object> getNaverAuthCallback(HttpServletResponse response, HttpServletRequest request) throws Exception {
		HashMap<String, Object> resultMap = new HashMap<String, Object>();
		//네이버 로그인 인증 시작
		String clientId = "osgm3bqYygYV49c1QPWl";//애플리케이션 클라이언트 아이디값";
	    String clientSecret = "1jYoDWu4_v";//애플리케이션 클라이언트 시크릿값";
	    String code = request.getParameter("code");
	    String state = request.getParameter("state");
	    String redirectURI = URLEncoder.encode("http://127.0.0.1:8080/login/callback", "UTF-8");
	    String json_string=""; //3번사용
	    String responseBody="";//2번사용
	    Map<String, String> requestHeaders = new HashMap<>();
	    String apiURL;
	    apiURL = "https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&";
	    apiURL += "client_id=" + clientId;
	    apiURL += "&client_secret=" + clientSecret;
	    apiURL += "&redirect_uri=" + redirectURI;
	    apiURL += "&code=" + code;
	    apiURL += "&state=" + state;
	    log.debug("apiURL="+ apiURL);
        requestHeaders.put("Authorization", null);
	    responseBody = get(apiURL,requestHeaders);
	    log.debug("responseBody="+ responseBody);
	    json_string = responseBody;//토큰 값 변수에 저장
        //네이버 로그인 인증 끝

	    //네이버 프로필 정보 가져오기 시작 
	    ObjectMapper objectMapper = new ObjectMapper();
	    NaverTokenVO jsonToken = objectMapper.readValue(json_string, NaverTokenVO.class);
	    String token = jsonToken.getAccess_token(); // 네이버 로그인 접근 토큰;
        String header = "Bearer " + token; // Bearer 다음에 공백 추가
        String openApiURL = "https://openapi.naver.com/v1/nid/me";
        requestHeaders.put("Authorization", header);
        responseBody = get(openApiURL,requestHeaders);
        log.debug("responseBody="+ responseBody);
        json_string = responseBody;//프로필 값 변수에 저장
        NaverResponseVO jsonResponse = objectMapper.readValue(json_string, NaverResponseVO.class);
        log.debug("jsonProfile="+ jsonResponse.getResultcode() + jsonResponse.getMessage());
        //네이버 프로필 정보 가져오기 끝
        //로그인 권한 부여 시작
        if(jsonResponse.getResultcode().equals("00")) {
        	ObjectMapper mapper = new ObjectMapper();
        	NaverProfileVO jsonProfile = mapper.convertValue(jsonResponse.getResponse(), NaverProfileVO.class);
        	log.debug("jsonProfile="+ jsonProfile);
        	log.debug("jsonProfile.getName()="+ jsonProfile.getName());
        	LoginVO loginVO = new LoginVO();
            loginVO.setName(jsonProfile.getName());
            loginVO.setId(jsonProfile.getEmail());
            loginVO.setUniqId(jsonProfile.getEmail());
            loginVO.setUserSe("USR");
            loginVO.setGroupNm("ROLE_USER");
	        String jwtToken = jwtTokenUtil.generateToken(loginVO);
			String username = jwtTokenUtil.getUserSeFromToken(jwtToken);
	    	log.debug("Dec jwtToken username = "+username);
	    	String groupnm = jwtTokenUtil.getInfoFromToken("groupNm", jwtToken);
	    	log.debug("Dec jwtToken groupnm = "+groupnm);//생성한 토큰에서 스프링시큐리티용 그룹명값 출력
	    	//서버사이드 권한 체크 통과를 위해 삽입
	    	//EgovUserDetailsHelper.isAuthenticated() 가 그 역할 수행. DB에 정보가 없으면 403을 돌려 줌. 로그인으로 튕기는 건 프론트 쪽에서 처리
	    	request.getSession().setAttribute("LoginVO", loginVO);
			resultMap.put("resultVO", loginVO);
			resultMap.put("jToken", jwtToken);
			resultMap.put("resultCode", "200");
			resultMap.put("resultMessage", "성공 !!!");
        }else {
        	resultMap.put("resultVO", null);
			resultMap.put("resultCode", "300");
			resultMap.put("resultMessage", egovMessageSource.getMessage("fail.common.login"));
        }
        //로그인 권한 부여 끝
		return resultMap;
	}
	//외부 데이터 파싱(아래)
	private static String get(String openApiUrl, Map<String, String> requestHeaders){
		HttpURLConnection con = connect(openApiUrl);
        try {
            con.setRequestMethod("GET");
            for(Map.Entry<String, String> header :requestHeaders.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }
            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { // 정상 호출
                return readBody(con.getInputStream());
            } else { // 에러 발생
                return readBody(con.getErrorStream());
            }
        } catch (IOException e) {
            throw new RuntimeException("API 요청과 응답 실패", e);
        } finally {
            con.disconnect();
        }
    }
	//외부 URL 커넥션 호출(아래)
	private static HttpURLConnection connect(String apiUrl){
        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection)url.openConnection();
        } catch (MalformedURLException e) {
            throw new RuntimeException("API URL이 잘못되었습니다. : " + apiUrl, e);
        } catch (IOException e) {
            throw new RuntimeException("연결이 실패했습니다. : " + apiUrl, e);
        }
    }
	//외부 프로필 내용 출력(아래)
    private static String readBody(InputStream body){
        InputStreamReader streamReader = new InputStreamReader(body);
        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();
            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }
            return responseBody.toString();
        } catch (IOException e) {
            throw new RuntimeException("API 응답을 읽는데 실패했습니다.", e);
        }
    }
}

/**
 * 네이버 토큰 변수 VO
 * @author kimilguk
 *
 */
@Getter
class NaverTokenVO {
	private String access_token;
    private String refresh_token;
    private String token_type;
    private String expires_in;
}

/**
 * 네이버 프로필 변수 VO
 * @author kimilguk
 *
 */
@Getter
class NaverResponseVO {
	private String resultcode;
    private String message;
    private Object response;
}

/**
 * 네이버 프로필 변수 VO
 * @author kimilguk
 *
 */
@Getter
class NaverProfileVO {
    private String id;
    private String email;
    private String name;
}