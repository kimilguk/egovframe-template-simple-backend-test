package egovframework.let.uat.esm.service.impl;

import java.util.Map;

import org.egovframe.rte.fdl.cmmn.EgovAbstractServiceImpl;
import org.springframework.stereotype.Service;

import egovframework.let.uat.esm.service.EgovSiteManagerService;
import lombok.RequiredArgsConstructor;

/**
 * 사이트관리자의 로그인 비밀번호를 변경 처리하는 비즈니스 구현 클래스
 * 
 * @author 공통서비스 개발팀
 * @since 2023.04.15
 * @version 1.0
 * @see
 *
 *      <pre>
 * << 개정이력(Modification Information) >>
 *
 *   수정일      수정자          수정내용
 *  -------    --------    ---------------------------
 *   2023.04.15  김일국          최초 생성
 *   2024.08.29  이백행          컨트리뷰션 롬복 생성자 기반 종속성 주입
 *
 *      </pre>
 */
@Service
@RequiredArgsConstructor
public class EgovSiteManagerServiceImpl extends EgovAbstractServiceImpl implements EgovSiteManagerService {

	private final SiteManagerDAO siteManagerDAO;

	/**
	 * 기존 비번과 비교하여 변경된 비밀번호를 저장한다.
	 * 
	 * @param map데이터 String: login_id, old_password, new_password
	 * @return 성공시 1
	 * @throws Exception
	 */
	@Override
	public Integer updateAdminPassword(Map<?, ?> map) throws Exception {
		return siteManagerDAO.updateAdminPassword(map);
	}
}
