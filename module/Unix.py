import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Info import Info
import datetime



class Unix:
    def U_01(self,host):
        command1 = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
        command2 = r"grep pam_securetty /etc/pam.d/login | grep -v '^\s*#'"
        is_safe = False
        permit_is_safe = False
        pam_is_safe = False
        score = 0

        # if host["os"] == "rocky":
        #     command = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command1,time)
        #print(response)
        #2. 결과값에서 필요한 정보를 뽑아낸다.
        for line in response.splitlines():
            if "PermitRootLogin" in line:
                result = line.strip()
                break
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "no" in result.lower():
            permit_is_safe = True
            # score = "3"

        response2 = util.para_connect(host, command2, time)

        for line in response2.splitlines():
            if "auth" in line and "required" in line and "pam_securetty.so" in line:
                pam_is_safe = True
                break

        if permit_is_safe and pam_is_safe:
            score = 3
            is_safe = True

        command = command1 + ", " + command2
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
        # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"U_01",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info
    
    def U_02(self, host):
        command = "grep -E '^(minlen|dcredit|ucredit|lcredit|ocredit|difok|retry)' /etc/security/pwquality.conf"
        pwquality_is_safe = False
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)

        required_values = {
            "minlen": "8",
            "dcredit": "0",
            "ucredit": "0",
            "lcredit": "0",
            "ocredit": "0",
            "difok": "1",
            "retry": "3"
        }

        result_lines = []
        match_count = 0

        for line in response.splitlines():
            line = line.strip()
            for key in required_values:
                if line.startswith(key):
                    result_lines.append(line)
                    if f"{key} = {required_values[key]}" in line.replace(" ", ""):
                        match_count += 1
                    break

        result = "\n".join(result_lines)

        if match_count == len(required_values):
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_02", command, result, is_safe, score)

        return info

    #def U_03(self, host):
        command = "grep -E 'pam_unix.so|pam_faillock.so|pam_tally.so|pam_pwquality.so' /etc/pam.d/system-auth"
        is_safe = False
        score = 0

        time = 10

        response = util.para_connect(host,command,time)

        for line in response.splitlines():
            if "pam_faillock.so preauth audit deny" in line:
                result = line.strip()
                break

        if "unlock_time" in result.lower():
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"U_03",command,result,is_safe,score)

        return info
    
    def U_04(self, host):
        command1 = r'awk -F: \'($2 != "x") {print $1 " → " $2}\' /etc/passwd'
        command2 = r'sudo awk -F: \'($2 == "" || $2 == "*" || $2 == "!") {print $1 " → " $2}\' /etc/shadow'

        is_safe = False
        passwd_is_safe = False
        shadow_is_safe = False
        score = 0

        time = 10

        response = util.para_connect(host,command1,time)

        for line in response.splitlines():
            if "daemon" in line:
                result = line.strip()
                break

        if "*" in result.lower():
            passwd_is_safe = True
            score = 3

        response2 = util.para_connect(host, command2, time)

        for line in response2.splitlines():
            if "sync" in line:
                shadow_is_safe = True
                break

        if passwd_is_safe and shadow_is_safe:
            score = 3
            is_safe = True

        command = command1 + ", " + command2

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"U_01",command,result,is_safe,score)

        return info
    
    def U_05(self, host):
        command = "ls -ld /root"
        is_safe = False
        score = 0

        time = 10

        response = util.para_connect(host,command,time)

        for line in response.splitlines():
            if "dr" in line:
                result = line.strip()
                break

        if "drwx------" in result.lower():
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"U_05",command,result,is_safe,score)

        return info
    
    def U_06(self, host):
        command = "find / -nouser -print"
        is_safe = True
        score = 3
        result = "정상: 출력된 사용자 없는 파일 없음"

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            line = line.strip()
            if not line.startswith("find:"):
                is_safe = False
                score = 0
                result = line
                break

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_06", command, result, is_safe, score)

        return info

    def U_07(self, host):
        command = "ls -l /etc/passwd"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-rw-r--r--") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_07", command, result, is_safe, score)

        return info

    def U_08(self, host):
        command = "ls -l /etc/shadow"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-r--------") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_08", command, result, is_safe, score)

        return info

    def U_09(self, host):
        command = "ls -l /etc/hosts"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-rw-------") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_09", command, result, is_safe, score)

        return info
    
    def U_10(self, host):
        command = "ls -l /etc/inetd.conf"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-rw-------") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_10", command, result, is_safe, score)

        return info

    def U_11(self, host):
        command = "ls -l /etc/rsyslog.conf"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-rw-r-----") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_11", command, result, is_safe, score)

        return info
    
    def U_12(self, host):
        command = "ls -l /etc/services"
        is_safe = False
        score = 0
        result = ""

        time = 10
        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            result = line.strip()
            break

        if result.startswith("-rw-r--r--") and " root " in result:
            is_safe = True
            score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_12", command, result, is_safe, score)

        return info
    
    def U_13(self,host):
        import datetime

        command = (
            "find / -xdev \\( -perm -4000 -o -perm -2000 \\) "
            "-type f -exec ls -alL {} \\; 2>/dev/null"
        )
        timeout = 20
        is_safe = True
        score = 3
        result_lines = []

        # 허용된 SUID/SGID 디렉토리
        WHITELIST_DIRS = [
            "/bin/",
            "/sbin/",
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/lib/",
            "/usr/libexec/",
            "/lib/",
            "/lib64/",
            "/usr/lib64/",
            "/usr/local/bin/",
            "/usr/local/sbin/",
            "/usr/local/libexec/"
        ]

        try:
            response = util.para_connect(host, command, timeout)
            suspect_files = []

            for line in response.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 9:
                    filepath = parts[-1]
                    if not any(filepath.startswith(d) for d in WHITELIST_DIRS):
                        suspect_files.append(line)

            if suspect_files:
                is_safe = False
                score = 0
                result_lines.append("의심스러운 SUID/SGID 파일 존재:")
                result_lines.extend(suspect_files)
            else:
                result_lines.append("허용된 디렉토리 외 SUID/SGID 파일 없음 (안전)")

        except Exception as e:
            is_safe = False
            score = 0
            result_lines.append(f"오류 발생: {str(e)}")

        result = "\n".join(result_lines)
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_13", command, result, is_safe, score)

        return info
    
    def U_14(self, host):
        #점검 대상 환경 변수 파일
        env_files = [
            ".profile", ".kshrc", ".cshrc", ".bashrc",
            ".bash_profile", ".login", ".exrc", ".netrc"
        ]
        home_path = "/home"
        time = 10
        is_safe = True
        score = 3
        findings = []

        for filename in env_files:
            check_path = f"{home_path}/*/{filename}"
            # 파일 권한 확인
            command = f"ls -l {check_path} 2>/dev/null"
            response = util.para_connect(host, command, time)

            for line in response.splitlines():
                parts = line.split()
                if len(parts) < 9:
                    continue

                permission = parts[0]
                owner = parts[2]
                filepath = parts[-1]
                username = filepath.split("/")[-2]

                # 조건 1: 기타 사용자(o)에 쓰기 권한 있는 경우
                if permission[-3] == 'w':
                    findings.append(f"{filepath}: 기타 사용자(o) 쓰기 권한 있음")
                    is_safe = False

                # 조건 2: 소유자가 계정 주인이 아닌 경우
                elif owner != username:
                    findings.append(f"{filepath}: 소유자({owner}) ≠ 계정 사용자({username})")
                    is_safe = False

        if not is_safe:
            score = 0
            result = "\n".join(findings)
        else:
            result = "홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 적절함"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        command_used = f"ls -l {home_path}/*/.환경파일들"
        info = Info(host.id, date, "U_14", command_used, result, is_safe, score)
        return info
    
    def U_15(self, host):
        # 사용자로부터 검사할 파일 경로를 입력받음

        # 입력 받은 파일에 대해 SUID/SGID 여부를 확인
        command = "find / -type f -perm -2 -exec ls -l {} \\; 2>/dev/null"
        time = 10
        is_safe = False
        score = 0
        result = ""

        try:
            response = util.para_connect(host, command, time)

            if response.strip() == "":
                result = " writable 파일이 존재하지 않음 (안전)"
                is_safe = True
                score = 3
            else:
                is_safe = False
                score = 0
                file_list = response.strip().splitlines()
                result = f"world-writable 파일 존재 (총 {len(file_list)}개):\n" + "\n".join(file_list[:10])
                if len(file_list) > 10:
                    result += f"\n... (이하 생략)"

        except Exception as e:
            is_safe = False
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_15", command, result, is_safe, score)
        return info

    def U_16(self, host):
        command = "find /dev -type f -exec ls -l {} \\; 2>/dev/null"
        time = 10
        is_safe = True
        score = 3
        result = ""

        try:
            response = util.para_connect(host, command, time)

            suspicious = []
            for line in response.splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    # major, minor 번호가 없는 일반 파일: character/block device 아님
                    if "," not in parts[4] and "," not in parts[5]:
                        suspicious.append(line)

            if suspicious:
                is_safe = False
                score = 0
                result = f"/dev 내 비정상 device 파일 발견 (총 {len(suspicious)}개):\n" + "\n".join(suspicious[:10])
                if len(suspicious) > 10:
                    result += "\n... (이하 생략)"
            else:
                result = "/dev 디렉터리 내 모든 device 파일 정상"

        except Exception as e:
            is_safe = False
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_16", command, result, is_safe, score)
        return info

    def U_17(self, host):
    
        time = 10
        is_safe = True
        score = 3
        findings = []
        result = ""

        # 점검 대상 파일들
        files_to_check = ["/etc/hosts.equiv"]
        # 사용자 홈 디렉토리 대상 포함
        get_users_cmd = "ls -d /home/*"
        try:
            home_dirs = util.para_connect(host, get_users_cmd, time).splitlines()
            for user_home in home_dirs:
                files_to_check.append(f"{user_home}/.rhosts")
        except Exception as e:
            findings.append(f"홈 디렉터리 탐색 실패: {str(e)}")
            is_safe = False

        for file in files_to_check:
            # 존재 여부 확인
            exist_cmd = f"test -f {file} && echo exists || echo missing"
            response = util.para_connect(host, exist_cmd, time).strip()
            if response != "exists":
                continue  # 파일 없으면 건너뜀

            # 1. 소유자 및 권한 확인
            stat_cmd = f"ls -l {file}"
            output = util.para_connect(host, stat_cmd, time).strip()
            parts = output.split()
            if len(parts) >= 3:
                owner = parts[2]
                perms = parts[0]
                if owner != "root":
                    findings.append(f"{file}: 소유자 비정상 ({owner})")
                    is_safe = False
                if perms[1:] != "rw-------":  # -rw------- (600) 비교
                    findings.append(f"{file}: 권한 비정상 ({perms})")
                    is_safe = False
            else:
                findings.append(f"{file}: ls 결과 파싱 실패")
                is_safe = False

            # 2. '+' 설정 확인
            grep_cmd = f"grep '^+' {file} || echo 'no_plus'"
            plus_result = util.para_connect(host, grep_cmd, time).strip()
            if plus_result != "no_plus":
                findings.append(f"{file}: '+' 신뢰 설정 감지됨")
                is_safe = False

        if not is_safe:
            score = 0
            result = "\n".join(findings)
        else:
            result = "/etc/hosts.equiv 및 $HOME/.rhosts 설정이 적절함"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_17", "파일 권한 및 내용 점검", result, is_safe, score)

    def U_18(self, host):
        time = 10
        is_safe = True
        score = 3
        findings = []
        result = ""

        # 점검 대상 파일 목록
        files_to_check = ["/etc/hosts.allow", "/etc/hosts.deny"]

        try:
            allow_exists = False
            deny_exists = False

            for file in files_to_check:
                check_cmd = f"test -f {file} && echo exists || echo missing"
                response = util.para_connect(host, check_cmd, time).strip()
                if file == "/etc/hosts.allow":
                    allow_exists = (response == "exists")
                    if not allow_exists:
                        findings.append(f"{file} 파일이 존재하지 않음")
                        is_safe = False
                if file == "/etc/hosts.deny":
                    deny_exists = (response == "exists")
                    if not deny_exists:
                        findings.append(f"{file} 파일이 존재하지 않음")
                        is_safe = False

            # /etc/hosts.deny에 ALL 차단 설정 확인
            if deny_exists:
                deny_cmd = "grep -E '^ALL|^ALL:ALL' /etc/hosts.deny || echo 'no_deny'"
                deny_result = util.para_connect(host, deny_cmd, time).strip()
                if "no_deny" in deny_result:
                    findings.append("/etc/hosts.deny에 ALL 차단 설정 없음")
                    is_safe = False

            # /etc/hosts.allow에 허용된 IP 또는 서비스 설정 확인
            if allow_exists:
                allow_cmd = "grep -v '^#' /etc/hosts.allow | grep -v '^$' || echo 'no_allow'"
                allow_result = util.para_connect(host, allow_cmd, time).strip()
                if "no_allow" in allow_result or allow_result.strip() == "":
                    findings.append("/etc/hosts.allow에 허용된 설정 없음")
                    is_safe = False

        except Exception as e:
            result = f"명령 실행 오류: {str(e)}"
            is_safe = False
            score = 0
        else:
            if not is_safe:
                score = 0
                result = "\n".join(findings)
            else:
                result = "접속 IP 및 포트 제한이 적절히 설정되어 있음 (양호)"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_18", "접속 IP 및 포트 제한 설정 점검", result, is_safe, score)


    def U_20(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        # 익명 FTP 계정 존재 여부 확인 명령
        command = "grep -E '^ftp|^anonymous' /etc/passwd || echo 'no_ftp_user'"

        try:
            response = util.para_connect(host, command, time).strip()

            if response == "no_ftp_user" or response == "":
                result = "익명 FTP 계정이 존재하지 않음 (양호)"
            else:
                is_safe = False
                score = 0
                result = "익명 FTP 계정 존재 확인됨:\n" + response

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_20", command, result, is_safe, score)

    def U_22(self, host):
        time = 10
        is_safe = True
        score = 3
        findings = []
        result = ""

        # 점검 대상 파일 및 경로
        cron_files = [
            "/usr/bin/crontab",
            "/etc/cron.allow",
            "/etc/cron.deny"
        ]

        try:
            for file in cron_files:
                check_cmd = f"stat -c '%n %a %U' {file} 2>/dev/null || echo 'missing:{file}'"
                response = util.para_connect(host, check_cmd, time).strip()

                if response.startswith("missing:"):
                    continue  # 파일이 없는 경우 점검 제외

                parts = response.split()
                if len(parts) != 3:
                    findings.append(f"{file}: 정보 파싱 실패 → {response}")
                    is_safe = False
                    continue

                path, perm, owner = parts
                perm = int(perm)

                # 조건1: 파일 소유자가 root인지
                if owner != "root":
                    findings.append(f"{file}: 소유자({owner})가 root가 아님")
                    is_safe = False

                # 조건2: 권한이 640 이하인지
                if perm > 640:
                    findings.append(f"{file}: 권한({perm})이 640 초과")
                    is_safe = False

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"
        else:
            if not is_safe:
                score = 0
                result = "\n".join(findings)
            else:
                result = "crond 관련 주요 파일의 소유자 및 권한 설정이 적절함"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_22", "crond 파일 권한 및 소유자 점검", result, is_safe, score)

    def U_24(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        try:
            # ps 명령어를 통해 NFS 관련 프로세스 확인
            command = "ps -ef | egrep 'nfs|statd|lockd' | grep -v grep || echo 'no_nfs_running'"
            response = util.para_connect(host, command, time).strip()

            if response == "no_nfs_running" or response == "":
                result = "NFS 관련 데몬(nfs, statd, lockd)이 실행되고 있지 않음"
            else:
                is_safe = False
                score = 0
                result = "NFS 관련 데몬이 실행 중임:\n" + response

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        return Info(host.id, date, "U_24", "NFS 데몬 실행 여부 점검", result, is_safe, score)
    
    def U_026(self, host):
        command = "systemctl is-active autofs"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        if result == "inactive":
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_026", command, result, is_safe, score)
        return info


    def U_029(self, host):
        command = "systemctl is-active tftp"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()  # 명령어 결과는 보통 한 줄 (active / inactive)

        if result == "inactive":
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_029", command, result, is_safe, score)
        return info

    
    
    def U_030(self, host):
        command = "sendmail -d0.1 </dev/null"
        is_safe = False
        version_is_safe = False
        score = 0
        time = 10

        # 1. 명령어 실행
        response = util.para_connect(host, command, time)

        # 2. 결과 분석
        for line in response.splitlines():
            if "Version" in line:
                result = line.strip()
                version = result.split()[1]  # 예: 8.16.1
                break

        # 3. 취약 버전 여부 확인
        major, minor, patch = map(int, version.split("."))
        if (major, minor, patch) > (8, 16, 1):
            version_is_safe = True

        # 4. 점수 및 상태 설정
        if version_is_safe:
            is_safe = True
            score = 3

        # 5. Info 객체 생성 및 반환
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_030", command, result, is_safe, score)
        return info



    def U_031(self, host):
        command = 'cat /etc/mail/sendmail.cf | grep "R$*" | grep "Relaying denied"'
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)

        # 기본 결과
        result = "Relaying 설정 라인을 찾지 못함"

        for line in response.splitlines():
            result = line.strip()
            if result.startswith("#"):
                # 주석이면 취약
                is_safe = False
                score = 0
            else:
                # 주석 아니면 양호
                is_safe = True
                score = 3
            break  # 첫 줄만 검사하고 종료

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_031", command, result, is_safe, score)

        return info



    def U_032(self, host):
        command = "grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)

        result = "PrivacyOptions 설정 라인 미발견"

        for line in response.splitlines():
            line = line.strip()
            result = line
            # restrictqrun 포함 여부 체크
            if "restrictqrun" in line:
                is_safe = True
                score = 3
                break
            else:
                is_safe = False
                score = 0
                # 계속 다른 라인 찾아볼 수 있음 (break 없이)
                # 필요하면 break 해도 됨

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_032", command, result, is_safe, score)

        return info



    def U_033(self, host):
        command = "named -v"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)

        result = ""
        version = None

        for line in response.splitlines():
            if "BIND" in line:
                result = line.strip()
                parts = result.split()
                if len(parts) > 1:
                    version_str = parts[1]  # 예: '9.16.23-RH'
                    # 패치 뒤에 붙은 문자 제거
                    patch_part = version_str.split(".")[2]
                    patch_num = patch_part.split("-")[0]
                    version = (int(version_str.split(".")[0]),
                            int(version_str.split(".")[1]),
                            int(patch_num))
                break

        if version is None:
            # 버전 정보 못 찾음
            is_safe = False
            score = 0
        else:
            if version > (9, 10, 3):
                is_safe = True
                score = 3

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_033", command, result, is_safe, score)
        return info

    def U_034(self, host):
        command = "cat /etc/named.conf | grep 'allow-transfer'"
        is_safe = False  # 기본은 취약
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        # 결과가 비어 있지 않고 any가 아닌 경우 양호
        if result and "any" not in result.lower():
            is_safe = True
            score = 3
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_034", command, result, is_safe, score)
        return info




    def U_035(self, host):
        command = 'grep "Options.*Indexes" /etc/httpd/conf/httpd.conf | grep -v "^#"'
        is_safe = True  # 처음엔 양호라고 가정하고 시작
        score = 3
        time = 10
        result_lines = []

        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            line = line.strip()
            result_lines.append(line)
            # -Indexes가 없는 경우는 Indexes가 켜진 상태 → 취약
            if "Indexes" in line and "-Indexes" not in line:
                is_safe = False
                score = 0
                # 더 이상 검사할 필요 없음
                break

        if not result_lines:
            result = "Indexes 옵션 없음 (양호)"
        else:
            result = "\n".join(result_lines)

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_035", command, result, is_safe, score)
        return info



    def U_036(self, host):
        command = "grep -E '^User|^Group' /etc/httpd/conf/httpd.conf"
        is_safe = False  # 기본을 취약으로 시작
        score = 0        # 기본 점수도 취약으로 시작
        time = 10
        result_lines = []

        response = util.para_connect(host, command, time)

        for line in response.splitlines():
            line = line.strip()
            result_lines.append(line)
            parts = line.split()
            # root가 아닌 User와 Group이 있다면 양호로 판단
            if len(parts) >= 2 and parts[1].lower() != "root":
                is_safe = True
                score = 3

        if not result_lines:
            result = "User/Group 설정 없음 (확인 필요)"
        else:
            result = "\n".join(result_lines)

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_036", command, result, is_safe, score)
        return info
    
    def U_37(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        httpd_conf = "/etc/httpd/conf/httpd.conf"

        try:
            # AllowOverride 설정 확인
            cmd = f"grep -i 'AllowOverride' {httpd_conf} 2>/dev/null || echo 'no_allowoverride'"
            response = util.para_connect(host, cmd, time).strip()

            if response == "no_allowoverride" or response == "":
                is_safe = False
                score = 0
                result = f"{httpd_conf} 파일에 AllowOverride 설정이 없음"
            else:
                # AllowOverride None 포함 여부 확인
                override_lines = [line for line in response.splitlines() if "allowoverride" in line.lower()]
                has_none = any("none" in line.lower() for line in override_lines)

                if has_none:
                    result = "AllowOverride 설정이 None으로 설정되어 있어 상위 디렉토리 접근이 제한됨"
                else:
                    is_safe = False
                    score = 0
                    result = f"AllowOverride 설정이 'None'이 아님:\n" + "\n".join(override_lines)

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{httpd_conf} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_37", "웹 서비스 상위 디렉토리 접근 제한 설정 점검", result, is_safe, score)

    def U_38(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        # 점검 대상 디렉터리 목록
        suspect_paths = [
            "/var/www/manual",
            "/var/www/html/manual",
            "/etc/httpd/manual",
            "/usr/local/apache2/manual",
            "/usr/local/apache2/htdocs/manual"
        ]

        try:
            found = []

            for path in suspect_paths:
                cmd = f"test -d {path} && echo exists:{path} || echo missing:{path}"
                response = util.para_connect(host, cmd, time).strip()
                if response.startswith("exists:"):
                    found.append(response.split(":", 1)[1])

            if found:
                is_safe = False
                score = 0
                result = "불필요한 Apache 매뉴얼 디렉터리가 존재함:\n" + "\n".join(found)
            else:
                result = "Apache 기본 매뉴얼 또는 불필요한 디렉터리가 존재하지 않음"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_38", "Apache 불필요한 디렉터리 존재 여부 점검", result, is_safe, score)

    def U_39(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        httpd_conf = "/etc/httpd/conf/httpd.conf"

        try:
            #  FollowSymLinks 설정 여부 확인
            cmd = f"grep -i 'Options' {httpd_conf} 2>/dev/null | grep -i 'FollowSymLinks' || echo 'no_symlinks'"
            response = util.para_connect(host, cmd, time).strip()

            if response == "no_symlinks" or response == "":
                result = "Apache 설정에서 FollowSymLinks 옵션이 설정되어 있지 않음"
            else:
                is_safe = False
                score = 0
                result = f"Apache 설정에서 심볼릭 링크 허용(FollowSymLinks) 설정 발견됨:\n{response}"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{httpd_conf} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_39", "Apache 심볼릭 링크 설정 점검", result, is_safe, score)

    def U_40(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        httpd_conf = "/etc/httpd/conf/httpd.conf"

        try:
            # LimitRequestBody 설정 확인
            cmd = f"grep -i 'LimitRequestBody' {httpd_conf} 2>/dev/null || echo 'no_limit'"
            response = util.para_connect(host, cmd, time).strip()

            if response == "no_limit" or response == "":
                is_safe = False
                score = 0
                result = f"{httpd_conf} 파일에 LimitRequestBody 설정이 존재하지 않음"
            else:
                # 설정된 바이트 수 추출
                import re
                match = re.search(r'(?i)LimitRequestBody\s+(\d+)', response)
                if match:
                    limit = int(match.group(1))
                    if limit > 5000000:
                        is_safe = False
                        score = 0
                        result = f"설정된 파일 업로드 한도({limit} bytes)가 5MB를 초과함"
                    else:
                        result = f"파일 업로드/다운로드 제한이 적절히 설정됨: {response}"
                else:
                    is_safe = False
                    score = 0
                    result = f"LimitRequestBody 설정 구문 파싱 실패: {response}"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{httpd_conf} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_40", "파일 업로드 및 다운로드 용량 제한 설정 점검", result, is_safe, score)

    def U_41(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        httpd_conf = "/etc/httpd/conf/httpd.conf"
        default_paths = "/var/www/html"

        try:
            # DocumentRoot 설정 확인
            cmd = f"grep -i '^DocumentRoot' {httpd_conf} 2>/dev/null || echo 'no_docroot'"
            response = util.para_connect(host, cmd, time).strip()

            if response == "no_docroot" or response == "":
                is_safe = False
                score = 0
                result = f"{httpd_conf} 파일에서 DocumentRoot 설정이 존재하지 않음"
            else:
                root_path = response.split()[-1].strip('"')

                if root_path in default_paths:
                    is_safe = False
                    score = 0
                    result = f"DocumentRoot가 기본 경로({root_path})로 설정됨"
                else:
                    result = f"DocumentRoot가 별도 디렉터리({root_path})로 설정되어 있음"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{httpd_conf} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_41", "Apache DocumentRoot 별도 디렉터리 설정 점검", result, is_safe, score)

    def U_42(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        try:
            #보안 업데이트 항목 확인
            cmd = "dnf updateinfo list security 2>/dev/null || echo 'no_updateinfo'"
            response = util.para_connect(host, cmd, time).strip()

            if response == "no_updateinfo" or response == "":
                is_safe = False
                score = 0
                result = "[✖] 보안 패치 정보 확인 불가 또는 결과 없음"
            elif "No security updates needed" in response:
                result = "[✔] 적용 가능한 보안 패치 없음\n→ 시스템이 최신 보안 상태 유지 중"
            else:
                is_safe = False
                score = 0
                result = "[✖] 적용되지 않은 보안 패치 존재함\n"
                result += " → dnf updateinfo list security 결과:\n"
                result += response

        except Exception as e:
            is_safe = False
            score = 0
            result = f"[!] 점검 실패: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_42", "최신 보안패치 및 벤더 권고사항 적용 점검", result, is_safe, score)


    def U_43(self, host):
        import re

        time = 10
        is_safe = False
        score = 0
        result = ""

        try:
            # 1. 로그인 기록 확인 (wtmp, btmp)
            login_check_cmd = "lastlog | grep -v '**Never logged in**' | wc -l"
            login_count = int(util.para_connect(host, login_check_cmd, time).strip())

            # 2. 실패 로그인 확인
            failed_login_cmd = "lastb | wc -l"
            failed_count = int(util.para_connect(host, failed_login_cmd, time).strip())

            # 3. sulog 존재 확인
            sulog_check_cmd = "test -f /var/log/sulog && echo 'exist' || echo 'not_found'"
            sulog_exists = util.para_connect(host, sulog_check_cmd, time).strip() == "exist"

            # 4. FTP 접근 로그 확인
            xferlog_check_cmd = "test -f /var/log/xferlog && echo 'exist' || echo 'not_found'"
            xferlog_exists = util.para_connect(host, xferlog_check_cmd, time).strip() == "exist"

            if login_count > 0 or failed_count > 0 or sulog_exists or xferlog_exists:
                is_safe = True
                score = 3
                result = (
                    f"[✔] 로그인 기록 {login_count}건, 실패 로그인 {failed_count}건 확인됨.\n"
                    f"[✔] sulog: {'존재함' if sulog_exists else '없음'}, xferlog: {'존재함' if xferlog_exists else '없음'}\n"
                    f" → 로그 분석 정기적으로 수행되고 있음"
                )
            else:
                result = (
                    "[✘] 로그인 기록 및 주요 로그 파일 존재하지 않거나 미수집 상태\n"
                    "→ 로그 분석 미수행으로 판단"
                )

        except Exception as e:
            result = f"[오류] 로그 점검 중 예외 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_43", "로그의 정기적 검토 및 보고 점검", result, is_safe, score)
    
    def U_52(self, host):
        command = "grep -Ev '^#' /etc/passwd | awk -F: '{print $3}'"  # UID만 출력하는 명령어
        
        is_safe = False  # 기본적으로 안전하다고 설정
        score = 2  # 기본 점수는 2점

        time = 10  # 명령어 실행 시간
        result1 = ""

        # 1. 명령어를 실행하여 UID 리스트를 가져옵니다.
        response = util.para_connect(host, command, time)
        uids = response.splitlines()
        # 2. UID 중복 여부 확인
        uid_seen = set()  # 이미 본 UID를 저장할 집합
        duplicate_uid_found = False  # 중복 UID 발견 여부를 추적하는 변수

        for uid in uids:
            if uid in uid_seen:
                duplicate_uid_found = True  # 중복 UID 발견
                result1 = uid
                break  # 중복이 한 번이라도 발견되면 반복문 종료
            uid_seen.add(uid)

        # 3. 중복 UID가 발견되면 안전하지 않음
        if duplicate_uid_found:
            is_safe = False  # 중복된 UID가 있으면 안전하지 않음
            score = 0  # 중복 UID가 있으면 점수는 0

        # 4. 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        result = result1 if duplicate_uid_found else "No Duplicates"
        info = Info(host.id, date, "U_52", command, result, is_safe, score)

        # 5. 정보 객체 반환
        return info



    def U_53(self, host):
        # 해당 명령어로 시스템 사용자 필터링
        command = "grep -Ev '^#' /etc/passwd | awk -F: '($3 < 1000 && $7 !~ /(false|nologin)$/ && $1 != \"root\")'"

        is_safe = False  # 기본적으로 안전하지 않다고 설정
        score = 0  # 점수 초기화

        # 명령어 실행 시간
        time = 10

        # 1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host, command, time)

        # 2. 결과값에서 필요한 정보를 뽑아낸다.
        system_accounts = []  # 로그인할 수 있는 시스템 계정들을 저장
        for line in response.splitlines():
            system_accounts.append(line.strip())

        # 3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if len(system_accounts) > 0:
            is_safe = True  # 로그인할 수 있는 시스템 계정이 있으므로 안전
            score = 1  # 시스템 계정이 잘 설정되었다는 점에서 높은 점수

        # 4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
        date = datetime.datetime.now().strftime("%Y-%m-%d")  # 현재 날짜를 yyyy-mm-dd 형식으로 생성

        # 점검 코드 "U_53"와, 결과에 맞는 변수들을 활용하여 정보를 기록
        info = Info(host.id, date, "U_53", command, system_accounts, is_safe, score)

        # 5. 정보 객체 반환
        return info



    def U_54(self, host):
        # 'TIMEOUT=600'을 /etc/profile에서 찾는 명령어
        command = "grep 'TIMEOUT=600' /etc/profile"
        
        is_safe = False  # 기본적으로 안전하지 않다고 설정
        score = 0  # 기본 점수는 0점

        time = 10  # 명령어 실행 시간

        # 1. 명령어를 실행하여 결과를 가져옵니다.
        response = util.para_connect(host, command, time)

        # 2. 결과값을 바탕으로 TIMEOUT 설정이 있는지 확인
        if response:
            # TIMEOUT=600 설정이 존재하면
            is_safe = True  # 안전하다고 판단
            score = 1  # 점수는 3점

        # 3. 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        result = "TIMEOUT=600 Found" if is_safe else "TIMEOUT=600 Not Found"
        info = Info(host.id, date, "U_54", command, result, is_safe, score)

        # 4. 정보 객체 반환
        return info


    def U_55(self, host):
        import subprocess
        # 파일 경로
        file_path = "/etc/hosts.lpd"
        
        is_safe = False  # 기본적으로 안전하다고 설정
        score = 3  # 기본 점수는 3점
        result = ""  # 결과 문자열 초기화

        time = 10  # 명령어 실행 시간

        # 1. /etc/hosts.lpd 파일이 존재하는지 확인
        file_exists = os.path.exists(file_path)

        if not file_exists:
            result = "LPD 서비스 미설치"
            is_safe = True
            score = 1
        else:
            # 2. 파일이 존재할 경우 권한 점검 (ls -l /etc/hosts.lpd)
            command = f"ls -l {file_path}"
            response = util.para_connect(host, command, time)

            # 3. 권한 확인
            if response:
                # 권한 확인 (파일 권한이 'rw-r--r--'와 같은지 확인)
                file_permissions = response.splitlines()[0].split()[0]  # 첫 번째 줄에서 파일 권한만 추출

                # 권한이 적절한지 여부 판단 (예: 644 또는 그 이하)
                if file_permissions != "-rw-------":
                    result = "파일 권한 불일치"
                    is_safe = False
                    score = 0
                else:
                    result = "파일 권한 정상"
                    score = 1
            else:
                result = "권한 확인 실패"
                is_safe = False
                score = 1

        # 4. 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_55", f"ls -l {file_path}", result, is_safe, score)

        # 5. 정보 객체 반환
        return info
    
    def U_56(self, host):
        # UMASK 값을 확인하는 명령어
        command = "umask"
        
        is_safe = False  # 기본적으로 안전하지 않다고 설정
        score = 0  # 기본 점수는 0점
        result = ""  # 결과 문자열 초기화
        time = 10  # 명령어 실행 시간

        # 1. 명령어를 실행하여 결과를 가져옵니다.
        response = util.para_connect(host, command, time)

        # 2. 결과값을 바탕으로 TIMEOUT 설정이 있는지 확인
        if response:
            umask_value = response.strip()
            
            # 3. UMASK 값이 022 이상인지 확인
            if int(umask_value, 8) >= 0o022:  # 022를 8진수로 비교
                result = umask_value
                print("test")
                score = 2  # UMASK 값이 022 이상이면 점수 3점
                is_safe = True  # 안전하다고 판단
            else:
                result = umask_value
                score = 0  # UMASK 값이 022 미만이면 점수 0점
                is_safe = False  # 안전하지 않음
        else:
            result = "UMASK 값 확인 실패"
            score = 0  # UMASK 값 확인 실패 시 안전하지 않음
            is_safe = False


        # 3. 정보 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_56", command, result, is_safe, score)

        # 4. 정보 객체 반환
        return info

    def U_62(self, host):
        command = "cat /etc/passwd | grep '^ftp:'"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        if result:
            parts = result.split(":")
            if len(parts) >= 7:
                shell = parts[-1]
                if shell in ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false"]:
                    is_safe = True
                    score = 2
        else:
            result = "ftp 계정 없음"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_062", command, result, is_safe, score)
        return info

    def U_57(self, host):
        command = "ls -ld /home/*"
        is_safe = True
        score = 2
        time = 10

        response = util.para_connect(host, command, time)
        lines = response.strip().split("\n")

        vulnerable_entries = []

        for line in lines:
            parts = line.split()
            if len(parts) < 9:
                continue  # 예외 라인 스킵

            perms = parts[0]      # 권한 문자열 예: drwxr-xr-x
            owner = parts[2]      # 소유자
            path = parts[8]       # 디렉토리 경로, 예: /home/jihun
            user = path.split('/')[-1]

            others_perms = perms[7:10]  # others 권한 3글자, 예: r-x, rwx 등
            o_write = perms[8]          # others 쓰기 권한 (8번째 문자)

            # 취약조건:
            # 1) 소유자와 디렉토리명이 다르거나
            # 2) others 쓰기 권한이 있을 때(w이면 취약)
            if owner != user or o_write == 'w':
                is_safe = False
                vulnerable_entries.append(line)

        if is_safe:
            result_text = "홈 디렉터리 소유자 및 권한 설정 양호"
        else:
            score = 0  # ⬅️ 취약한 경우 점수 0점으로 설정
            result_text = "[취약] 다음 홈 디렉터리에서 소유자 불일치 또는 others 쓰기 권한 발견:\n" + "\n".join(vulnerable_entries)

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_057", command, result_text, is_safe, score)
        return info

    
    
    def U_58(self, host):
        # 먼저 UID_MIN 값을 구하는 명령어
        command_uid = "grep '^UID_MIN' /etc/login.defs | awk '{print $2}'"
        uid_min = util.para_connect(host, command_uid, 5).strip()

        # 그 다음 uid_min 변수를 이용해 awk 명령 실행
        command_awk = f"awk -F: -v uid_min={uid_min} '$3 >= uid_min && $6 == \"/\" {{print $1, $3, $6}}' /etc/passwd"
        response = util.para_connect(host, command_awk, 5).strip()

        result_lines = [line.strip() for line in response.splitlines()]

        is_safe = True
        score = 2
        result_text = f"양호: '/'를 홈디렉토리로 사용하는 일반 사용자는 nobody만 존재\n\n실제 결과:\n{response}"

        others = [line for line in result_lines if line != "nobody 65534 /"]
        if others:
            is_safe = False
            score = 0
            result_text = (
                "[취약] '/'를 홈디렉토리로 사용하는 일반 사용자 발견:\n"
                + "\n".join(others)
            )

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_058", command_uid + " && " + command_awk, result_text, is_safe, score)
        return info



    
    def U_59(self, host):
        command = r'find / \( -type f -o -type d \) -name ".*" 2>/dev/null'
        time = 60  
        is_safe = True
        score = 1

        response = util.para_connect(host, command, time)
        results = response.strip().split("\n")

        
        suspicious_keywords = ['.sock', '.tmp', '.back', '.old']
        
        
        suspicious_files = [
            path for path in results
            if any(keyword in path.lower() for keyword in suspicious_keywords)
        ]

        
        if suspicious_files:
            is_safe = False
            score = 0
            result_text = "[취약] 다음과 같은 의심 파일(숨김 + 의심 확장자) 발견:\n" + "\n".join(suspicious_files)
        else:
            result_text = "양호: 의심스러운 숨김 파일 없음"

        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_059", command, result_text, is_safe, score)
        return info


    def U_60(self, host):
        ssh_cmd = "systemctl is-active sshd"
        telnet_cmd = "systemctl is-active telnet.socket"
        is_safe = False
        score = 0
        time = 10

        ssh_response = util.para_connect(host, ssh_cmd, time).strip()
        telnet_response = util.para_connect(host, telnet_cmd, time).strip()

        # SSH만 active이고 Telnet은 inactive 혹은 기타 상태일 때 양호
        if ssh_response == "active" and (telnet_response != "active"):
            is_safe = True
            score = 2
        else:
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        command = f"{ssh_cmd} & {telnet_cmd}"
        result = f"SSH: {ssh_response}, Telnet: {telnet_response}"
        info = Info(host.id, date, "U_061", command, result, is_safe, score)
        return info

    def U_61(self, host):
        command = "systemctl is-active vsftpd"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        if result == "inactive":
            is_safe = True
            score = 1
        elif result == "active":
            is_safe = False
            score = 0
        else:
            # 예기치 않은 결과 처리 (예: not-found 등)
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_066", command, result, is_safe, score)
        return info


    def U_63(self, host):
        command = "ls -l /etc/vsftpd/ftpusers"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        # 예: -rw-------. 1 root root 125 11월  7  2024 /etc/vsftpd/ftpusers
        if result and result.startswith("-"):
            parts = result.split()
            permissions = parts[0]    # -rw-------
            owner = parts[2]          # root
            group = parts[3]          # root

            # 권한을 숫자로 계산: rw------- → 600, rw-r--r-- → 644
            permission_str = permissions[1:10]  # rw-------
            perm_map = {'r': 4, 'w': 2, 'x': 1, '-': 0}
            perm_values = [
                sum([perm_map[c] for c in permission_str[0:3]]),
                sum([perm_map[c] for c in permission_str[3:6]]),
                sum([perm_map[c] for c in permission_str[6:9]])
            ]
            permission_num = int("".join(map(str, perm_values)))  # 예: 600

            if owner == "root" and permission_num <= 640:
                is_safe = True
                score = 1

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_063", command, result, is_safe, score)
        return info



    def U_64(self, host):
        command = "cat /etc/vsftpd/ftpusers | grep -E '^#?root$'"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        # result가 비어있지 않으면 검사
        if result:
            # 여러줄 나올 수도 있어서 줄 단위로 분리
            lines = result.splitlines()

            # 각 줄을 검사
            for line in lines:
                line = line.strip()
                if line == "root":
                    # root가 주석 없이 있으면 양호
                    is_safe = True
                    score = 2
                    break
                elif line == "#root":
                    # root가 주석처리 되어있으면 취약
                    is_safe = False
                    score = 0
                    break
        else:
            # 아예 root 관련 줄이 없으면, 보통 취약 판단할 수도 있지만 상황에 따라 다름
            # 여기서는 취약 처리
            is_safe = False
            score = 0
            result = "root 또는 #root 라인 없음"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_064", command, result, is_safe, score)
        return info



    def U_66(self, host):
        command = "systemctl is-active snmpd"
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response.strip()

        if result == "inactive":
            is_safe = True
            score = 2
        elif result == "active":
            is_safe = False
            score = 0
        else:
            # 예기치 않은 결과 처리 (예: not-found 등)
            is_safe = False
            score = 0

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "U_066", command, result, is_safe, score)
        return info
    
    def U_67(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        target_file = "/etc/snmp/snmpd.conf"

        try:
            # SNMP 설정 파일 내 public/private 문자열 포함 여부 확인
            command = f"grep -i 'public\\|private' {target_file} 2>/dev/null || echo 'no_default_string'"
            response = util.para_connect(host, command, time).strip()

            if response == "no_default_string" or response == "":
                result = "Community 이름이 public/private로 설정되어 있지 않음"
            else:
                is_safe = False
                score = 0
                result = f"Community 이름이 기본값(public/private)으로 설정됨:\n{response}"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{target_file} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_67", f"SNMP Community String 점검 - {target_file}", result, is_safe, score)

    def U_68(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        # 점검 대상 경고 메시지 파일
        banner_files = ["/etc/motd", "/etc/issue", "/etc/issue.net"]
        findings = []

        try:
            banner_configured = False

            for file in banner_files:
                cmd = f"test -f {file} && grep -v '^#' {file} | grep -v '^$' || echo 'empty_or_missing:{file}'"
                response = util.para_connect(host, cmd, time).strip()

                if response.startswith("empty_or_missing"):
                    findings.append(f"{file}: 파일 없음 또는 설정된 경고 메시지 없음")
                else:
                    banner_configured = True
                    findings.append(f"{file}: 경고 메시지 설정 확인됨")

            if banner_configured:
                result = "서버 로그인 시 경고 메시지가 적절히 설정되어 있음" + "\n".join(findings)
            else:
                is_safe = False
                score = 0
                result = "서버 로그인 시 경고 메시지가 설정되어 있지 않음" + "\n".join(findings)

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_68", "로그인 경고 메시지 점검", result, is_safe, score)

    def U_69(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        target_file = "/etc/exports"

        try:
            # 파일 존재 여부, 소유자, 권한 확인
            command = f"stat -c '%n %U %a' {target_file} 2>/dev/null || echo 'missing:{target_file}'"
            response = util.para_connect(host, command, time).strip()

            if response.startswith("missing"):
                result = f"{target_file} 파일이 존재하지 않음 (점검 제외)"
            else:
                path, owner, perm = response.split()
                perm = int(perm)

                # 소유자 확인
                if owner != "root":
                    findings.append(f"{target_file}: 소유자({owner})가 root가 아님")
                    is_safe = False

                # 권한 확인
                if perm > 644:
                    findings.append(f"{target_file}: 권한({perm})이 644 초과")
                    is_safe = False

                if is_safe:
                    result = f"{target_file} 소유자 및 권한 설정이 적절함"
                else:
                    score = 0
                    result = "\n".join(findings)

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_69", f"NFS 설정파일 권한 점검 - {target_file}", result, is_safe, score)

    def U_70(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""

        target_file = "/etc/mail/sendmail.cf"

        try:
            # PrivacyOptions 설정 확인
            command = f"grep -i 'PrivacyOptions' {target_file} 2>/dev/null || echo 'no_privacy_option'"
            response = util.para_connect(host, command, time).strip().lower()

            if "no_privacy_option" in response or response == "":
                is_safe = False
                score = 0
                result = f"{target_file} 파일에 PrivacyOptions 항목이 설정되어 있지 않음"
            elif "goaway" in response or ("noexpn" in response and "novrfy" in response):
                result = f"{target_file} 파일에 보안 옵션 설정 확인됨:\n{response}"
            else:
                is_safe = False
                score = 0
                result = f"{target_file} 파일에 noexpn, novrfy 또는 goaway 옵션이 없음:\n{response}"

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_70", "SMTP expn/vrfy 제한 설정 점검", result, is_safe, score)

    def U_71(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        httpd_conf = "/etc/httpd/conf/httpd.conf"

        try:
            # ServerTokens 설정 확인
            token_cmd = f"grep -i '^ServerTokens' {httpd_conf} 2>/dev/null || echo 'no_tokens'"
            token_result = util.para_connect(host, token_cmd, time).strip()

            # ServerSignature 설정 확인
            sign_cmd = f"grep -i '^ServerSignature' {httpd_conf} 2>/dev/null || echo 'no_signature'"
            sign_result = util.para_connect(host, sign_cmd, time).strip()

            # ServerTokens 판정
            if "prod" not in token_result.lower():
                is_safe = False
                findings.append(f"ServerTokens 설정 미흡 또는 누락: {token_result}")

            # ServerSignature 판정
            if "off" not in sign_result.lower():
                is_safe = False
                findings.append(f"ServerSignature 설정 미흡 또는 누락: {sign_result}")

            # 결과 구성
            if is_safe:
                result = "Apache 설정에서 ServerTokens=Prod, ServerSignature=Off 설정이 적절히 적용되어 있음 (양호)"
            else:
                score = 0
                result = "\n".join(findings)

        except Exception as e:
            is_safe = False
            score = 0
            result = f"{httpd_conf} 점검 중 오류 발생: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_71", f"Apache 정보 노출 방지 설정 점검 - {httpd_conf}", result, is_safe, score)

    def U_72(self, host):
        time = 10
        is_safe = True
        score = 3
        result = ""
        findings = []

        target_file = "/etc/syslog.conf"

        try:
            # 점검 기준에 필요한 로그 항목
            required_keywords = ["mail.debug", "*.info", "*.alert", "*.emerg"]

            # 설정 파일에서 각 항목 존재 여부 확인
            for keyword in required_keywords:
                cmd = f"grep -E '^{keyword}' {target_file} 2>/dev/null || echo 'missing:{keyword}'"
                response = util.para_connect(host, cmd, time).strip()

                if response.startswith("missing:"):
                    findings.append(f"{keyword} 항목 누락")
                    is_safe = False

            if is_safe:
                result = f"{target_file} 내 정책에 따른 주요 로그 항목이 적절히 설정되어 있음 (양호)"
            else:
                score = 0
                result = f"{target_file} 파일에 아래 로그 항목이 누락됨 (취약):\n" + "\n".join(findings)

        except Exception as e:
            is_safe = False
            score = 0
            result = f"명령 실행 오류: {str(e)}"

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "U_72", "시스템 로깅 정책 설정 점검", result, is_safe, score)



unix = Unix()

# Test
# 상황에 맞게 값 수정 가능
#from vo.Host import Host
#hosta = Host(1,"unix","rocky17","172.16.13.2","root","asd123!@")

#info = Unix.U_13(hosta)
#print(vars(info))
