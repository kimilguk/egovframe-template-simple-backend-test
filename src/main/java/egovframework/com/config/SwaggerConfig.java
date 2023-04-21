package egovframework.com.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;
// accessToken 입력 화면과 처리 라이브러리 추가(아래4줄)
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.service.*;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
	
	private static final String API_NAME = "Simple Homepage Project API";
	private static final String API_VERSION = "4.1.0";
	private static final String API_DESCRIPTION = "심플홈페이지 프로젝트 명세서";
	
	@Bean
	public Docket api() {
		return new Docket(DocumentationType.SWAGGER_2)
				.apiInfo(apiInfo())
				.select()
				.apis(RequestHandlerSelectors.any())
				.paths(PathSelectors.any())
				.build()
				.securityContexts(Arrays.asList(securityContext())) // 스웨그에서 컨텐츠 url 접근 시 인증처리를 위한 보안 규칙 호출
                .securitySchemes(Arrays.asList(apiKey())); // 스웨그 화면상단에 토큰값 입력하는 창 구조 호출
	}
	// accessToken 입력 화면 구조 
    private ApiKey apiKey() {
        return new ApiKey("Authorization", "Authorization", "header");
    }
    // 스웨그에서 컨텐츠 url 접근 시 인증처리를 위한 보안 규칙 추가(아래)
    private SecurityContext securityContext() {
        return springfox
                .documentation
                .spi.service
                .contexts
                .SecurityContext
                .builder()
                .securityReferences(defaultAuth()).forPaths(PathSelectors.any()).build();
    }
    // 토큰 인증영역 배열을 반환하는 매서드
    List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything"); // 인증영역 객체 생성
        AuthorizationScope[] authorizationScopeArray = new AuthorizationScope[1]; // 토큰 배열변수 선언
        authorizationScopeArray[0] = authorizationScope; // 토큰 배열변수에 인증영역 지정
        return Arrays.asList(new SecurityReference("Authorization", authorizationScopeArray));
    }
    
	public ApiInfo apiInfo() {
		return new ApiInfoBuilder()
				.title(API_NAME)
				.version(API_VERSION)
				.description(API_DESCRIPTION)
				.contact(new Contact("eGovFrame", "https://www.egovframe.go.kr/", "egovframesupport@gmail.com"))
				.build();
	}

}
