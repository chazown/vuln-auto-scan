import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime
import re
import pymysql

class Db:
    def D_01(self,host):
        command = """
        SELECT user, host, authentication_string
        FROM mysql.user
        WHERE user IN ('root', 'mysql');
        """
        is_safe = True
        score = 3

        
        result_rows = util.query(command)

        result_str = "\n".join(str(row) for row in result_rows)

        for user, host_addr, auth in result_rows:
            if auth is None or auth.strip().lower() == "invalid":
                is_safe = False
                score -= 2
            if host_addr.strip() == "%":
                is_safe = False
                score -= 1

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "D_01", command, result_str, is_safe, score)
        return info

    def D_02(self,host):
        # 기준일: 현재 시점에서 30일 전
        one_month_ago = datetime.datetime.now() - datetime.timedelta(days=30)

        # MariaDB의 general_log에서 접속 정보 가져오기
        command = """
        SELECT user_host, event_time
        FROM mysql.general_log
        WHERE command_type = 'Connect'
        ORDER BY event_time DESC;
        """

        rows = util.squery(host, command)

        # {user: 가장 마지막 로그인 시각} 저장
        last_login_map = {}

        # 로그에서 사용자명 추출
        user_pattern = re.compile(r'\[(.*?)\]')

        for user_host, event_time in rows:
            match = user_pattern.search(user_host)
            if match:
                user = match.group(1)
                if user not in last_login_map:
                    last_login_map[user] = event_time  # 최신 로그인만 저장됨 (DESC 정렬이므로)

        # mysql.user에서 전체 사용자 목록 가져오기
        user_list_query = "SELECT user FROM mysql.user;"
        all_users = util.squery(host, user_list_query)
        all_users = [u[0] for u in all_users]

        # 불필요한 계정 판별 (1개월 이상 로그인 없는 계정)
        old_accounts = []
        for user in all_users:
            last_login = last_login_map.get(user)
            if last_login is None:
                old_accounts.append((user, "NEVER LOGGED IN"))
            else:
                try:
                    login_time = datetime.datetime.strptime(str(last_login), "%Y-%m-%d %H:%M:%S.%f")
                    if login_time < one_month_ago:
                        old_accounts.append((user, str(last_login)))
                except:
                    old_accounts.append((user, f"INVALID DATE: {last_login}"))

        # 보안 점수 계산
        is_safe = not old_accounts
        score = 3 if is_safe else 0

        # 결과 문자열
        result_str = "\n".join([f"User: {user}, Last Login: {login}" for user, login in old_accounts]) \
                    if old_accounts else "No outdated accounts found."

        # Info 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "D_02", command, result_str, is_safe, score)
        return info

    def D_03(self,host):
        base_score = 3
        is_safe = True

        # 1) simple_password_check 설정 조회
        simple_check_cmd = "SHOW VARIABLES LIKE 'simple_password_check%';"
        simple_vars = util.squery(host, simple_check_cmd)

        # 딕셔너리로 정리
        simple_dict = {var: val for var, val in simple_vars}

        # 2) 패스워드 사용기간 조회
        lifetime_cmd = "SHOW VARIABLES LIKE 'default_password_lifetime';"
        lifetime_val = util.squery(host, lifetime_cmd)[0][1]
        lifetime_val = int(lifetime_val)

        # 3) 비밀번호 만료된 사용자 조회
        expired_cmd = "SELECT user, host, password_expired FROM mysql.user WHERE password_expired = 'Y';"
        expired_users = util.squery(host, expired_cmd)

        # 점검 결과 문자열 준비
        result_lines = []
        result_lines.append("Simple Password Check Settings:")
        for var, val in simple_vars:
            result_lines.append(f"  {var}: {val}")
        result_lines.append(f"default_password_lifetime: {lifetime_val}")
        result_lines.append("Expired users:")
        if expired_users:
            for user, host_addr, expired in expired_users:
                result_lines.append(f"  {user}@{host_addr} - password_expired={expired}")
        else:
            result_lines.append("  None")

        # 4) 복잡도 조건 체크
        cond_length = int(simple_dict.get('simple_password_check_minimal_length', '0')) >= 8
        cond_digits = simple_dict.get('simple_password_check_digits', '0') == '1'
        cond_letters_case = simple_dict.get('simple_password_check_letters_same_case', '0') == '1'
        cond_special = simple_dict.get('simple_password_check_other_characters', '0') == '1'

        if not (cond_length and cond_digits and cond_letters_case and cond_special):
            is_safe = False
            base_score -= 2
            result_lines.append("Password complexity policy NOT satisfied.")
        else:
            result_lines.append("Password complexity policy satisfied.")

        # 5) 패스워드 만료 사용자 있으면 점수 깎기
        if expired_users:
            is_safe = False
            base_score -= 1
            result_lines.append("There are expired user passwords.")

        # 6) Info 객체 반환
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        command = f"{simple_check_cmd}\n{lifetime_cmd}\n{expired_cmd}"
        result_str = "\n".join(result_lines)

        info = Info(host.id, date, "D_03", command, result_str, is_safe, base_score)
        return info

    def D_04(self,host):
        score = 3
        is_safe = True

        # 1) ALL PRIVILEGES 가진 사용자 조회 (root, mysql 제외)
        privileges_cmd = """
        SELECT user, host, Grant_priv 
        FROM mysql.user 
        WHERE Grant_priv = 'Y' AND user NOT IN ('root', 'mysql');
        """
        privileged_users = util.squery(host, privileges_cmd)

        # 결과 메시지 구성
        result_lines = []
        result_lines.append("Users with ALL PRIVILEGES (excluding root & mysql):")
        if privileged_users:
            for user, host_addr, grant in privileged_users:
                result_lines.append(f"  {user}@{host_addr} - Grant_priv={grant}")
            is_safe = False
            score = 0
            result_lines.append("Non-root/mysql users with ALL PRIVILEGES found.")
        else:
            result_lines.append("  None")
            result_lines.append("Only root and mysql have ALL PRIVILEGES.")

        # Info 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(
            host.id,
            date,
            "D_04",
            privileges_cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )

        return info

    def D_05(self,host):
        score = 3
        is_safe = True

        # 1) host명이 '%'인 사용자 조회
        wildcard_host_cmd = """
        SELECT user, host 
        FROM mysql.user 
        WHERE host = '%';
        """
        wildcard_users = util.squery(host, wildcard_host_cmd)

        # 결과 메시지 구성
        result_lines = []
        result_lines.append("Users with host = '%':")
        if wildcard_users:
            for user, host_addr in wildcard_users:
                result_lines.append(f"  {user}@{host_addr}")
            is_safe = False
            score = 0
            result_lines.append("Users with wildcard host '%' found.")
        else:
            result_lines.append("  None")
            result_lines.append("No users with wildcard host '%' found.")

        # Info 객체 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(
            host.id,
            date,
            "D_05",
            wildcard_host_cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )

        return info

    def D_06(self,host):
        score = 3
        is_safe = True

        # 1) 시스템 스키마(mysql)의 테이블에 접근 권한이 있는 사용자 조회 (root, mysql 계정 제외)
        system_priv_cmd = """
        SELECT DISTINCT grantee
        FROM information_schema.schema_privileges
        WHERE table_schema = 'mysql' AND privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE');
        """

        # grantee 형식이 `'user'@'host'` 형태이므로 user만 분리
        grantees = util.squery(host, system_priv_cmd)
        users_with_priv = set()
        for (grantee,) in grantees:
            # grantee 예: '`username`@`host`' 형식
            # ' 또는 ` 제거 후 분리
            cleaned = grantee.replace('`', '').replace("'", "")
            user = cleaned.split('@')[0]
            users_with_priv.add(user)

        # 시스템 계정 리스트 (필요시 추가)
        system_accounts = {'root', 'mysql', 'mysql.session', 'mysql.sys', 'mysql.infoschema'}

        # 시스템 계정을 제외한 사용자 필터링
        normal_users = [u for u in users_with_priv if u not in system_accounts]

        result_lines = []
        if normal_users:
            is_safe = False
            score = 0
            result_lines.append("Users with access to system tables:")
            for u in normal_users:
                result_lines.append(f"  {u}")
            result_lines.append("General users have access to system tables. Risky!")
        else:
            result_lines.append("No general users have access to system tables. Safe.")

        # 명령문 원문 저장
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(
            host.id,
            date,
            "D_06",
            system_priv_cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )

        return info
    
    def D_10(self,host):
        score = 3
        is_safe = True
        result_lines = []
        date = datetime.datetime.now().strftime("%Y-%m-%d")

        # 버전 및 버전 코멘트 조회
        version_cmd = "SELECT VERSION();"
        comment_cmd = "SELECT @@version_comment;"

        version_result = util.squery(host, version_cmd)
        comment_result = util.squery(host, comment_cmd)

        if version_result and comment_result:
            version = version_result[0][0]  # 예: '10.5.27-MariaDB'
            comment = comment_result[0][0]  # 예: 'MariaDB Server' 또는 'MySQL Community Server - GPL'

            result_lines.append(f"Version: {version}")
            result_lines.append(f"Version Comment: {comment}")

            # 버전 비교 함수
            def parse_version(vstr):
                return tuple(map(int, vstr.split('-')[0].split('.')))

            v_tuple = parse_version(version)

            if "MariaDB" in comment:
                # MariaDB 기준
                min_required = (10, 11, 0)  # EOL이 아닌 버전
                if v_tuple >= min_required:
                    result_lines.append("MariaDB version is up-to-date. Safe.")
                else:
                    score = 0
                    is_safe = False
                    result_lines.append(f"MariaDB version is outdated. Recommended: {'.'.join(map(str, min_required))} or higher.")
            elif "MySQL" in comment:
                # MySQL 기준
                min_required = (8, 0, 36)
                if v_tuple >= min_required:
                    result_lines.append("MySQL version is up-to-date. Safe.")
                else:
                    score = 0
                    is_safe = False
                    result_lines.append(f"MySQL version is outdated. Recommended: {'.'.join(map(str, min_required))} or higher.")
            else:
                score = 0
                is_safe = False
                result_lines.append("Unknown DBMS type. Manual check required.")
        else:
            score = 0
            is_safe = False
            result_lines.append("Failed to retrieve version information.")

        # 결과 객체 생성
        info = Info(
            host.id,
            date,
            "D_10",
            version_cmd + "\n" + comment_cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )
        return info
    
    def D_11(self,host):
        score = 3
        is_safe = True
        result_lines = []
        date = datetime.datetime.now().strftime("%Y-%m-%d")

        version_comment_cmd = "SELECT @@version_comment;"
        audit_vars_cmd = "SHOW GLOBAL VARIABLES LIKE 'server_audit%';"

        version_result = util.squery(host, version_comment_cmd)
        audit_vars_result = util.squery(host, audit_vars_cmd)

        if not version_result:
            result_lines.append("DBMS 정보를 확인할 수 없습니다.")
            is_safe = False
            score = 0
        else:
            dbms_type = version_result[0][0]
            result_lines.append(f"DBMS Version Comment: {dbms_type}")

            if "MariaDB" not in dbms_type:
                result_lines.append("Audit plugin is not supported on MySQL Community Edition.")
                is_safe = False
                score = 0
            else:
                # 감사 변수 분석
                audit_vars = {k: v for (k, v) in audit_vars_result}

                # 1) logging 확인
                logging_status = audit_vars.get("server_audit_logging", "").upper()
                if logging_status != "ON":
                    result_lines.append(f"[감점 -1] Audit logging is OFF (현재 값: {logging_status})")
                    score -= 1
                else:
                    result_lines.append("Audit logging is ON.")

                # 2) mode 확인
                audit_mode = audit_vars.get("server_audit_mode", "")
                if audit_mode == "0":
                    result_lines.append(f"[감점 -1] Audit mode is set to 0 (비활성 상태)")
                    score -= 1
                else:
                    result_lines.append(f"Audit mode is set to {audit_mode} (0이 아님, 통과).")

                # 3) events 설정 확인
                events = audit_vars.get("server_audit_events", "")
                if not events.strip():
                    result_lines.append("[감점 -1] Audit events 설정이 비어 있습니다.")
                    score -= 1
                else:
                    result_lines.append(f"Audit events 설정됨: {events}")

                # 최종 판정
                if score < 3:
                    is_safe = False
                    result_lines.append(f"총 {3 - score}점 감점. 감사 정책이 완전히 적용되지 않았습니다.")
                else:
                    result_lines.append("감사 정책이 충분히 적용되어 있습니다. (만점)")

        info = Info(
            host.id,
            date,
            "D_11",
            audit_vars_cmd + "\n" + version_comment_cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )
        return info
    

    def D_13(self,host):
        score = 3
        is_safe = True
        result_lines = []
        violations = []

        cmd = """
            SELECT user_host
            FROM mysql.general_log
            WHERE command_type = 'Connect'
        """

        try:
            rows = util.squery(host, cmd)
        except Exception as e:
            return Info(
                host.id,
                datetime.datetime.now().strftime("%Y-%m-%d"),
                "D_13",
                cmd,
                f"❌ 점검 실패: {str(e)}",
                False,
                0
            )

        ip_to_users = {}
        user_to_ips = {}

        for (user_host,) in rows:
            try:
                # 예: '[root] @ 172.16.0.9' 또는 '[root] @ localhost []'
                if '@' not in user_host:
                    continue  # 잘못된 형식 무시

                user_part, ip_part = user_host.split('@', 1)
                user = user_part.strip().strip('[]')
                ip = ip_part.strip()

                # ip가 비어있는 경우 제외하거나 'unknown'으로 대체
                if not ip:
                    ip = "unknown"

                ip_to_users.setdefault(ip, set()).add(user)
                user_to_ips.setdefault(user, set()).add(ip)

            except Exception:
                continue  # malformed line 무시


        for ip, users in ip_to_users.items():
            if len(users) > 1:
                violations.append(f"⚠️ IP {ip} 에서 여러 계정 접속 감지: {', '.join(users)}")

        for user, ips in user_to_ips.items():
            if len(ips) > 1:
                violations.append(f"⚠️ 계정 {user} 이 여러 IP에서 접속 감지: {', '.join(ips)}")

        if violations:
            score = 0
            is_safe = False
            result_lines.append("🚨 사용자별 고유 계정/접속 정책 위반 발견:")
            result_lines.extend(violations)
        else:
            result_lines.append("✅ 모든 사용자가 고유 계정으로 접근하고 있습니다.")

        return Info(
            host.id,
            datetime.datetime.now().strftime("%Y-%m-%d"),
            "D_13",
            cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )

    def D_15(self,host):
        score = 3
        is_safe = True
        cmd = "SHOW VARIABLES LIKE 'max_connect_errors';"

        try:
            rows = util.squery(host, cmd)
            # rows 예: [('max_connect_errors', '100')]
            value = int(rows[0][1])
        except Exception as e:
            return Info(
                host.id,
                datetime.datetime.now().strftime("%Y-%m-%d"),
                "D_15",
                cmd,
                f"❌ 점검 실패: {str(e)}",
                False,
                0
            )

        if value > 10:
            score = 0
            is_safe = False
            result = f"🚨 max_connect_errors 값이 너무 높음: {value} (10 이하 권장)"
        else:
            result = f"✅ max_connect_errors 값이 적절함: {value}"

        return Info(
            host.id,
            datetime.datetime.now().strftime("%Y-%m-%d"),
            "D_15",
            cmd,
            result,
            is_safe,
            score
        )

    def D_16(self,host):
        score = 3
        is_safe = True
        result_lines = []
        violations = []

        target_paths = [
            "/usr/bin/mariadb",
            "/usr/bin/mysql",
            "/usr/libexec/mariadbd",
        ]

        # 각 경로에서 파일의 권한과 경로를 stat로 확인
        cmd_parts = []
        for path in target_paths:
            # 경로가 파일일 수도 있고 디렉토리일 수도 있으니 모두 처리
            # -f: 파일, -exec stat로 권한과 경로 출력
            cmd_parts.append(f"if [ -d {path} ]; then find {path} -type f -exec stat -c '%a %n' {{}} \\;; "
                            f"elif [ -f {path} ]; then stat -c '%a %n' {path}; fi")

        cmd = "\n".join(cmd_parts)

        try:
            result = util.para_connect(host, cmd, 1)
        except Exception as e:
            return Info(
                host.id,
                datetime.datetime.now().strftime("%Y-%m-%d"),
                "D_16",
                cmd,
                f"❌ 점검 실패: {str(e)}",
                False,
                0
            )

        for line in result.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            perm_str, filepath = parts
            try:
                perm = int(perm_str)
            except ValueError:
                continue

            if perm > 644:
                is_safe = False
                score = 0
                violations.append(f"🚨 {filepath} 권한이 {perm}로 644 보다 높음")

        if is_safe:
            result_lines.append("✅ 점검 대상 파일들의 권한이 모두 644 이하로 안전하게 설정되어 있습니다.")
        else:
            result_lines.append("❌ 권한이 644 보다 높은 파일이 발견되었습니다:")
            result_lines.extend(violations)

        return Info(
            host.id,
            datetime.datetime.now().strftime("%Y-%m-%d"),
            "D_16",
            cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )

    def D_17(self,host):
        score = 3
        is_safe = True
        result_lines = []
        violations = []

        # OS 종류 판별
        os_check_cmd = "cat /etc/os-release | grep '^ID='"
        os_result = util.para_connect(host, os_check_cmd, 1).strip().lower()
        
        if "rocky" in os_result:
            os_type = "rocky"
            target_paths = ["/etc/my.cnf", "/etc/my.cnf.d"]
        elif "ubuntu" in os_result:
            os_type = "ubuntu"
            target_paths = [
                "/etc/mysql/my.cnf",
                "/etc/mysql/conf.d",
                "/etc/mysql/mariadb.conf.d"
            ]
        else:
            return Info(
                host.id,
                datetime.datetime.now().strftime("%Y-%m-%d"),
                "D_17",
                os_check_cmd,
                "❌ OS 종류 식별 실패",
                False,
                0
            )

        # 권한 점검
        for path in target_paths:
            cmd = f"stat -c '%a' {path} 2>/dev/null"
            perm_result = util.para_connect(host, cmd, 1).strip()

            if perm_result != "600":
                violations.append(f"🚨 {path} 의 권한이 600이 아님 (현재: {perm_result or '존재하지 않음'})")

        if violations:
            score = 0
            is_safe = False
            result_lines.append("❌ 다음 파일 또는 디렉토리의 권한이 600이 아님:")
            result_lines.extend(violations)
        else:
            result_lines.append("✅ 모든 설정 파일의 권한이 600으로 안전하게 설정되어 있습니다.")

        return Info(
            host.id,
            datetime.datetime.now().strftime("%Y-%m-%d"),
            "D_17",
            "\n".join([os_check_cmd] + [f"stat -c '%a' {p}" for p in target_paths]),
            "\n".join(result_lines),
            is_safe,
            score
        )

    def D_19(self,host):
        score = 0
        is_safe = False
        result_lines = []

        cmd = "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME = 'simple_password_check';"

        try:
            rows = util.squery(host, cmd)
        except Exception as e:
            return Info(
                host.id,
                datetime.datetime.now().strftime("%Y-%m-%d"),
                "D_19",
                cmd,
                f"❌ 점검 실패: {str(e)}",
                False,
                0
            )

        if not rows:
            result_lines.append("❌ simple_password_check 플러그인이 설치되어 있지 않습니다.")
        else:
            status = rows[0][1].upper()
            if status == "ACTIVE":
                score = 3
                is_safe = True
                result_lines.append("✅ simple_password_check 플러그인이 활성화되어 있습니다.")
            else:
                result_lines.append(f"❌ simple_password_check 플러그인이 활성화되어 있지 않습니다 (현재 상태: {status})")

        return Info(
            host.id,
            datetime.datetime.now().strftime("%Y-%m-%d"),
            "D_19",
            cmd,
            "\n".join(result_lines),
            is_safe,
            score
        )


db = Db()

# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"Db","db1","172.16.0.90","root","asd123!@")

#info = db.D_21(hosta)
#print(vars(info))

#result = util.squery(hosta,"SELECT * FROM host")
#print(result)


