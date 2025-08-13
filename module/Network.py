
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime
import re



class Network:
    # def N_01(host):
    #     command = "ip a"
    #     is_safe = False
    #     score = 0

    #     #명령어가 여러 줄일 때만 수정 필요
    #     time = 10

    #     #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
    #     response = util.para_connect(host,command,time)
    #     #print(reponse)
    #     #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
    #     result = response
    #     #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
    #     if "ens160" in result :
    #         is_safe = True
    #         score = 3
    #     else :
    #         print("no")
    #     #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
    #         # date(날짜 정보) 생성
    #     date = datetime.datetime.now().strftime("%Y-%m-%d")
    #     #print(date)
    #     info = Info(host.id,date,"W_01",command,result,is_safe,score)
    #     #5. 정보 객체 반환
    #     return info

    def N_01(self,host):
        command = "show run | section username"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response

        # 보안 기준:
        # 1. 기본 계정인 'cisco', 'admin' 등을 사용하는지 확인
        # 2. password 0 (평문) 방식 사용 여부 확인
        if ("username cisco password 0" in result or
            "username admin password 0" in result):
            is_safe = False
            score = 0
        else:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_01", command, result, is_safe, score)
        return info
        
    def N_02(self,host):
        command = "show run | section username"
        is_safe = False
        score = 0
        time = 10

        # 명령어 실행 결과 받아오기
        result = util.net_connect(host, command, time)

        # 결과 줄별로 나누기
        lines = result.splitlines()

        # 점검 로직: 평문 비밀번호 사용 여부 확인
        for line in lines:
            if "password 0" in line:  # 평문 비밀번호 사용 시
                is_safe = False
                score = 0
                break
        else:
            # 평문 비밀번호가 전혀 없으면 안전하다고 판단
            is_safe = True
            score = 3

        # 날짜 정보 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        result = result.replace("\n", " ")
        # 결과 객체 생성
        info = Info(host.id, date, "N_02", command, result, is_safe, score)

        return info

    def N_03(self,host):
        command = "show run | se username"
        is_safe = False
        score = 0

        # 명령어가 여러 줄일 때만 조정 필요
        time = 10

        # 1. host에 명령어 전송
        response = util.net_connect(host, command, time)

        # 2. 결과를 변수에 저장
        result = response
        #print (response)
        # 3. 암호화 설정 점검: username 라인 중 password 7 또는 secret 5 포함 여부 체크
        #    일반적으로 password 7 (암호화된 password) 또는 secret 5 (암호화된 시크릿)
        if " password 0 " in result:
            is_safe = False
            score = 0
        elif " password 7 " in result or " secret 5 " in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        # 4. 결과 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_03", command, result, is_safe, score)

        # 5. 결과 반환
        return info

    def N_04(self,host):
        command = "show run | section vty"
        is_safe = False
        score = 0
        time = 10

        result = util.net_connect(host, command, time)

        # \n 제거 및 문자열 정리
        cleaned_result = result.replace("\n", " ")

        # VTY 접근제한 확인: access-class가 설정되어 있어야 안전
        if "access-class" in cleaned_result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_04", command, cleaned_result, is_safe, score)

        return info


    def N_05(self,host):
        command = "show running-config | include line|exec-timeout"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response

        # 조건: exec-timeout이 한 줄 이상 있는지 확인
        if "exec-timeout" in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_05", command, result, is_safe, score)
        return info

    def N_06(self,host):
        command = "show version"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response

        # 예시 기준: IOS 버전이 15.x 이상이면 최신으로 간주
        # (조직 정책에 따라 판단 기준 변경 가능)
        if "Version 15" in result or "Version 16" in result or "Version 17" in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_06", command, result, is_safe, score)
        return info

    def N_07(self,host):
        command = "show snmp"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # SNMP 관련 설정이 없으면 안전한 것으로 판단
        # 참고: 단순화된 로직 - 실제로는 more precise하게 조정 가능
        if "community" not in result and "location" not in result and "contact" not in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_07", command, result, is_safe, score)
        return info

    def N_08(self,host):
        command = "show running-config | include snmp-server community"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # 기본 community 문자열 검사
        if "public" in result or "private" in result:
            is_safe = False
            score = 0
        else:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_08", command, result, is_safe, score)
        return info

    def N_09(self,host):
        command = "show running-config | include snmp-server community"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # snmp-server community line 중에 acl 키워드가 있는지 확인
        # 예: snmp-server community public RO 10
        if "acl" in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_09", command, result, is_safe, score)
        return info

    def N_10(self,host):
        command = "show running-config | include snmp-server community"
        is_safe = True  # 기본은 안전하다고 가정
        score = 3
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # RW 또는 write 권한이 포함되어 있으면 위험
        if " rw" in result or "write" in result:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_10", command, result, is_safe, score)
        return info

    def N_11(self,host):
        command = "show running-config | include tftp"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # 1) tftp-server 설정 여부 확인
        if "tftp-server" not in result:
            # TFTP 서비스 미사용 → 안전
            is_safe = True
            score = 3
        else:
            # 2) tftp-server가 존재하면 ACL(예: access-class) 여부 확인
            # 단순히 access-class 포함 여부 체크 (필요시 세분화 가능)
            if "access-class" in result or "acl" in result:
                is_safe = True
                score = 3
            else:
                is_safe = False
                score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_11", command, result, is_safe, score)
        return info


    def N_12(self,host):
        command = "show running-config | include ip verify"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # ip verify source 설정이 존재하면 안전
        if "ip verify source" in result:
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_12", command, result, is_safe, score)
        return info

    def N_13(self,host):
        commands = [
            "show running-config | include control-plane",
            "show running-config | include storm-control",
            "show running-config | include class-map",
            "show running-config | include policy-map",
            "show access-lists"
        ]

        is_safe = False
        score = 0
        time = 15
        full_result = ""

        for cmd in commands:
            response = util.net_connect(host, cmd, time)
            full_result += response.lower()

        # DDoS 방어 관련 키워드 존재 여부 판단 예시
        keywords = ["control-plane", "storm-control", "class-map", "policy-map", "ddos", "rate-limit"]

        if any(keyword in full_result for keyword in keywords):
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_13", " / ".join(commands), full_result, is_safe, score)
        return info


    def N_14(self,host):
        command = "show ip interface brief"
        is_safe = True
        score = 3
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()
        used_interfaces = []

        lines = result.splitlines()
        for line in lines:
            if line.strip() == "" or line.startswith("interface"):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            interface = parts[0]
            ip_address = parts[1]
            status = parts[4]

            # IP가 할당되어 있으면 사용 중 인터페이스로 간주
            if ip_address != "unassigned":
                used_interfaces.append(interface)

        # 두 번째로 다시 돌면서 미사용 인터페이스가 shutdown 상태인지 검사
        for line in lines:
            if line.strip() == "" or line.startswith("interface"):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            interface = parts[0]
            status = parts[4]

            # 사용하지 않는 인터페이스인데, up 상태면 is_safe = False
            if interface not in used_interfaces:
                if status not in ["administratively", "administratively down", "down"]:
                    is_safe = False
                    score = 0
                    break

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_14", command, result, is_safe, score)
        return info


    def N_15(self,host):
        command = "show running-config | include username"
        is_safe = True
        score = 2
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        lines = result.splitlines()
        total_users = 0
        admin_users = 0

        for line in lines:
            if "username" in line:
                total_users += 1
                if "privilege 15" in line:
                    admin_users += 1

        # 관리자 계정이 너무 많으면 위험 (예: 전체의 50% 이상, 또는 2개 초과 등 기준 적용 가능)
        if total_users == 0 or admin_users == 0:
            is_safe = False
            score = 0
        elif admin_users > 2 or admin_users / total_users > 0.5:
            is_safe = False
            score = 0
        else:
            is_safe = True
            score = 2

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_15", command, result, is_safe, score)
        return info


    def N_16(self,host):
        command = "show running-config | section line vty"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        # 안전한 경우: ssh만 허용
        if "transport input ssh" in result and "telnet" not in result:
            is_safe = True
            score = 2
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_16", command, result, is_safe, score)
        return info


    def N_17(self,host):
        command = "show running-config | section line aux"
        is_safe = True  # 기본은 안전으로 가정
        score = 2
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        if "line aux" in result:
            # aux 라인이 활성 상태인 경우 점검
            if "transport input none" in result or "no exec" in result or "exec-timeout" in result:
                is_safe = True
                score = 2
            else:
                # 아무 제한 없이 login만 걸려있으면 위험
                if "login" in result or "transport input" in result:
                    is_safe = False
                    score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_17", command, result, is_safe, score)
        return info


    def N_18(self,host):
        command = "show running-config | section banner"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        if "banner login" in result or "banner exec" in result:
            # 간단하게 'unauthorized', 'prohibited', 'warning' 같은 키워드 있는지 확인
            if any(keyword in result for keyword in ["unauthorized", "prohibited", "warning", "illegal", "access denied"]):
                is_safe = True
                score = 2

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_18", command, result, is_safe, score)
        return info


    def N_19(self,host):
        command = "show running-config | include logging host"
        is_safe = False
        score = 0
        time = 10

        response = util.net_connect(host, command, time)
        result = response.lower()

        if "logging host" in result:
            is_safe = True
            score = 1

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_19", command, result, is_safe, score)
        return info

    def N_20(self,host):
        command = "show running-config | include logging"
        is_safe = False
        score = 0

        # 명령어가 여러 줄일 때만 조정 필요
        time = 10

        # 1. host에 명령어 전송
        response = util.net_connect(host, command, time)

        # 2. 결과를 변수에 저장
        result = response
        #print (response)
        # 3. 정규표현식 사용해서 버퍼사이즈의 유무 체크, 사이즈  잘라서 최소용량에
        #    부합하는지 확인

        match = re.search(r'logging buffered\s+(\d+)', result)
        if match:
            buffer_value = int(match.group(1))
            #buffer_value = int(match.split()[-1])
            if buffer_value >= 16000:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
        else:
            is_safe = False
            score = 0


        # 4. 결과 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "N_20", command, result, is_safe, score)

        # 5. 결과 반환
        return info
    
    def N_22(self,host):
            command1 = "show running-config | include ntp"
            command2 = "show ntp associations"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response1 = util.net_connect(host, command1, time) #ntp설정확인
            response2 = util.net_connect(host, command2, time) # *표시가 있다면 동기화 O
                                                #  없으면 동기화 X
            #has_synced = any('*' in line for line in lines)
            has_synced = any(line.strip().startswith('*') for line in response2.splitlines())
            # 2. 결과를 변수에 저장
            #result = response
            #print (response)

            # response2 줄별로 나누기
            lines = response2.strip().splitlines()
            # 마지막 줄은 설명이라 제외
            lines_to_check = lines[:-1] if len(lines) > 1 else []

            # 동기화된 줄(*로 시작하는 줄)이 있는지 체크
            has_synced = any(line.lstrip().startswith('*') for line in lines_to_check)

            if 'ntp server' in response1 and has_synced:
                score = 2
                is_safe = True
            else:
                score = 0
                is_safe = False

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            command = f"{command1} && {command2}"
            result = f"{response1.strip()}\n---\n{response2.strip()}"
            info = Info(host.id, date, "N_22", command, result, is_safe, score)

            # 5. 결과 반환
            return info

    def N_23(self,host):
            command = "show running-config | include ^service timestamps"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response
            required_debug = "service timestamps debug datetime msec show-timezone"
            required_log = "service timestamps log datetime msec show-timezone"
            #print (response)
            # 3. 정규표현식 사용해서 버퍼사이즈의 유무 체크, 사이즈  잘라서 최소용량에
            #    부합하는지 확인

            if required_debug in response or required_log in response:
                is_safe = True
                score = 1
            else:
                is_safe = False
                score = 0

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_23", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_24(self,host): 
            command = "show running-config | include service tcp-keepalives"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response
            #print (response)
            in_enabled = 'service tcp-keepalives-in' in response
            out_enabled = 'service tcp-keepalives-out' in response
            # 3. 정규표현식 사용해서 버퍼사이즈의 유무 체크, 사이즈  잘라서 최소용량에
            #    부합하는지 확인

            if in_enabled and out_enabled:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_24", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_25(self,host):  #서비스 기본 차단
            command = "show running-config | include finger"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response
            #print (response)
            finger_enabled = 'ip finger' in response

            # 3. 정규표현식 사용해서 버퍼사이즈의 유무 체크, 사이즈  잘라서 최소용량에
            #    부합하는지 확인

            if not finger_enabled :
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_25", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_26(self,host): # 동작 및 확인 X 
            command = "show running-config | include ^ip http"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            has_https = "ip http server" in response
            has_access_class = "ip http access-class" in response
            # 2. 결과를 변수에 저장
            result = response
            #print (response)
            finger_enabled = 'ip finger' in response

            # 3.
            if not has_https:
                is_safe = True
                score = 2
            else:
                if has_access_class:
                    is_safe = True
                    score = 2
                else:
                    is_safe = False
                    score = 0



            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_26", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    

    def N_27(self,host):
            command = "show running-config | include small-servers"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response
            tcp_enabled = "service tcp-small-servers" in response
            udp_enabled = "service udp-small-servers" in response

            #print (response)
            # 3. 정규표현식 사용해서 버퍼사이즈의 유무 체크, 사이즈  잘라서 최소용량에
            #    부합하는지 확인

            if not tcp_enabled and not udp_enabled:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_27", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_28(self,host):
            command = "show running-config | include bootp"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 

            if "no ip bootp server" in result:
                # 'no ip bootp server' 있거나 아무것도 안 나옴 → 비활성화 상태로 간주
                is_safe = True
                score = 2
            else : 
                # BOOTP 서비스가 활성화되어 있음 → 취약
                is_safe = False
                score = 0
    

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_28", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_29(self,host):
            command = "show running-config | include cdp"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if "cdp run" in result and "no cdp run" not in result:
                is_safe = False
                score = 0
            elif "no cdp run" in result:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_29", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_30(self,host):
            command = "show running-config | include directed-broadcast"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            enabled = "ip directed-broadcast" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if not enabled:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_30", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_31(self,host):
            command = "show running-config | include source-route"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            enabled = "ip source-route" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if not enabled or "no ip source-route" in response:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_31", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_32(self,host):
            command = "show running-config | section interface"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            disabled = "no ip proxy-arp" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if not disabled:
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                

        # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_32", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_33(self,host):
            command = "show running-config | include  redirects"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            
            # 2. 결과를 변수에 저장
            result = response
            lines = response.strip().splitlines()
            current_interface = ""
            interface_config = {}
            active_interfaces = []


            # 3. 인터페이스 블록 파싱
            for line in lines:
                line = line.strip()

                if line.startswith("interface"):
                    current_interface = line
                    interface_config[current_interface] = []
                elif current_interface:
                    interface_config[current_interface].append(line)

            # 2. 각 인터페이스에서 shutdown 여부와 필수 설정 확인
            for intf, config in interface_config.items():
                is_shutdown = any("shutdown" in line for line in config)
                if is_shutdown:
                    continue  # shutdown된 인터페이스는 제외

                has_no_redirects = any("no ip redirects" in line for line in config)
                has_no_unreachables = any("no ip unreachables" in line for line in config)

                if not (has_no_redirects and has_no_unreachables):
                    # 하나라도 없으면 취약
                    is_safe = False
                    score = 0
                    break  # 하나만 빠져 있어도 전체를 취약으로 판단
                        

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_33", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_34(self,host):
            command = "show running-config | include ip identd"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            enabled = "ip identd" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if not enabled :
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                

        # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_34", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_35(self,host):
            command = "show running-config | include ip domain lookup"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            disabled = "no ip domain lookup" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if disabled :
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                    

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_35", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
        
    def N_36(self,host):
            command = "show running-config | include service pad"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            disabled = "no service pad" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if disabled :
                is_safe = True
                score = 2
            else:
                is_safe = False
                score = 0
                    

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_36", command, result, is_safe, score)

            # 5. 결과 반환
            return info
            
    def N_37(self,host):
            command = "show running-config | section interface"
            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            enabled = "ip mask-reply" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if  enabled :
                is_safe = True
                score = 0
            else:
                is_safe = False
                score = 2
                    

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_37", command, result, is_safe, score)

            # 5. 결과 반환
            return info
    
    def N_38(self,host): # XXXXX
            command = "show monitor session 1 or session 2"
            command = "running-config | include switchport port-security"

            is_safe = False
            score = 0

            # 명령어가 여러 줄일 때만 조정 필요
            time = 10

            # 1. host에 명령어 전송
            response = util.net_connect(host, command, time)
            enabled = "ip mask-reply" in response

            # 2. 결과를 변수에 저장
            result = response

            #print (response)
            # 3. 
            if  enabled :
                is_safe = True
                score = 0
            else:
                is_safe = False
                score = 1
                    

            # 4. 결과 정보 객체 생성
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            info = Info(host.id, date, "N_37", command, result, is_safe, score)

            # 5. 결과 반환
            return info

network = Network()

# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"network","R1","172.16.0.195","cisco","cisco")

#info = Network.N_23(hosta)
#print(vars(info))


