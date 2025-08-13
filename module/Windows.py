import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime
import re


class Windows:
    
    def W_01(self,host):
        command = """powershell -Command "Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Select-Object Name, SID" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response.split('\n')[3].strip()
        
        if "Administrator" in response :
            safety = False
            print("계정명 Administrator임. 보안상 취약")
        else :
            safety = True
            print("계정명 Administrator아님. 보안상 양호")
        
        with open('C:\\Users\\TJ\\Desktop\\W22_security_policy.inf', 'r', encoding='utf-8') as f:
            content = f.read()
        if "PasswordComplexity" in content:
            safety1 = True
            print("비밀번호 복잡성 정책 활성화. 보안상 양호")
        else :
            safety1 = False
            print("비밀번호 복잡성 정책 비활성화. 보안상 취약")
            
        if safety == True and safety == safety1:
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_01",command,result,is_safe,score)
        return info
    
    def W_02(self,host):
        command = """powershell -Command "Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object Name, Enabled" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response.split('\n')[3].strip()
        
        if "True" in response :
            safety = False
            print("Guest계정 활성화. 보안상 취약")
        else :
            safety = True
            print("Guest계정 비활성화. 보안상 양호")
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_02",command,result,is_safe,score)
        return info
    
    def W_04(self,host):
        command = "Check LockoutBadCount"
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10

        with open('C:\\Users\\TJ\\Desktop\\W22_security_policy.inf', 'r', encoding='utf-8') as f:
            for line in f :
                if "LockoutBadCount" in line :
                    line = line.strip()
                    result = line
                    value = int(line.split('=')[-1].strip())
                    print(f"계정 잠금 임계값: {value}")
        if 0 < value <= 5 :
            safety = True
            print("계정 잠금 임계값 5이하. 보안상 안전")
        elif value > 5 :
            safety = False
            print("계정 잠금 임계값 6이상. 보안상 취약")
        else :
            safety = False
            print("계정 잠금 임계값 미설정. 보안상 취약")
            
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_04",command,result,is_safe,score)
        return info
    
    def W_05(self,host):
        command = """powershell -Command "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'StorePasswords'" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        if "Get-ItemProperty" in response :
            safety = True
            print("해독 가능한 암호화 설정 없음. 보안상 양호")
            result = "해독 가능한 암호화 설정 없음"
        else :
            for line in response.splitlines() :
                if "StorePasswords" in line :
                    line = line.strip()
                    result = line
                    value = line.split(':')[-1].strip()
                    if value == "0" :
                        print("해독 가능한 암호 저장 비활성화. 보안상 양호")
                        safety = True
                    else :
                        print("해독 가능한 암호 저장 활성화. 보안상 취약")
                        safety = False
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
            
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_05",command,result,is_safe,score)
        return info
    
    def W_07(self,host):
        command = """powershell -Command "$default=@('ADMIN$','C$','D$','IPC$','PRINT$'); Get-SmbShare | Where-Object {($default -notcontains $_.Name) -and $_.Path} | ForEach-Object { Write-Host \\"`n공유 폴더: $($_.Name) - $($_.Path)\\"; (Get-Acl $_.Path).Access | Where-Object { $_.IdentityReference -like '*Everyone*' } | Select IdentityReference, FileSystemRights, AccessControlType }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        for line in response.splitlines() :
            if "Everyone" in line :
                result = line.strip()
        
        if "Everyone" in response :
            print("공유 디렉터리 내 Everyone 권한 존재. 보안상 취약")
            safety = False
        else :
            print("공유 디렉터리 내 Everyone 권한 없음. 보안상 양호")
            safety = True
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_07",command,result,is_safe,score)
        return info
    
    def W_08(self,host):
        command = """powershell -Command "Get-SmbShare | Where-Object { $_.Name -match '^[A-Z]\$$' } | Select-Object Name, Path" """
        command1 = """powershell -Command "try { (Get-ItemProperty -Path \'HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanServer\\\\Parameters\' -Name AutoShareServer -ErrorAction Stop).AutoShareServer } catch { Write-Output \'NoSetting\' }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        response1 = util.para_connect(host,command1,time)
        
        if "Name" in response :
            print("하드디스크 기본 공유 존재. 보안상 취약")
            safety = False
            result = "하드디스크 기본 공유 존재"
        else :
            print("하드디스크 기본 공유 없음. 보안상 양호")
            safety = True
            result = "하드디스크 기본 공유 없음"
        
        if "NoSetting" in response1 :
            safety1 = False
            print("레지스트리의 AutoShareServer 설정 없음. 보안상 취약")
        else :
            for line in response1.splitlines() :
                if "AutoShareServer" in line :
                    line = line.strip()
                    value = line.split(':')[-1].strip()
                    if value == "0" :
                        print("레지스트리의 AutoShareServer 비활성화. 보안상 양호")
                        safety1 = True
                    else :
                        print("레지스트리의 AutoShareServer 활성화. 보안상 취약")
                        safety1 = False
                        
        if safety == True and safety == safety1:
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_08",command,result,is_safe,score)
        return info
    
    def W_11(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath 'IIS:\' -Name enabled" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
                if "Value" in line :
                    if "IsInherited" not in line :
                        line = line.strip()
                        result = line
                        value = line.split(':')[-1].strip()
                        if value == "False" :
                            print("디렉터리 브라우징 기능 비활성화. 보안상 양호")
                            safety = True
                        else :
                            print("디렉터리 브라우징 기능 활성화. 보안상 취약")
                            safety = False
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_11",command,result,is_safe,score)
        return info
    
    def W_12(self,host):
        command = """powershell -Command "try { (Get-Acl 'C:\inetpub\scripts' -ErrorAction Stop).Access | Where-Object { $_.IdentityReference -like '*Everyone*' } | Select IdentityReference, FileSystemRights, AccessControlType } catch { Write-Output 'CGI Not Installed' }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        if "CGI Not Installed" in response :
            print("CGI 미설치. 보안상 양호")
            safety = True
        else :
            for line in response.splitlines() :
                if "Everyone" in line :
                    if "Allow" in line :
                        if "Modify" in line :
                            print("Everyone에 과도한 권한 할당. 보안상 취약")
                            safety = False
                        elif "Write" in line :
                            print("Everyone에 과도한 권한 할당. 보안상 취약")
                            safety = False
                        elif "FullControll" in  line :
                            print("Everyone에 과도한 권한 할당. 보안상 취약")
                            safety = False
                        else :
                            print("Everyone 권한 설정 양호함. 보안상 양호")
                            safety = True
                            
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
                    
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_12",command,result,is_safe,score)
        return info
    
    def W_13(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -PSPath 'IIS:\' -Name allowDoubleEscaping" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
                if "Value" in line :
                    if "IsInherited" not in line :
                        line = line.strip()
                        result = line
                        value = line.split(':')[-1].strip()
                        if value == "False" :
                            print("URL에서의 Escape문자 차단(상위 디렉터리로의 이동 차단). 보안상 양호")
                            safety = True
                        else :
                            print("URL에서의 Escape문자 허용(상위 디렉터리로의 이동 허용). 보안상 취약")
                            safety = False
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_13",command,result,is_safe,score)
        return info
    
    def W_14(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-WebVirtualDirectory -Site 'Default Web Site'" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "Name" in response :
            print("가상 디렉터리 존재. 보안상 취약")
            safety = False
        else :
            print("가상 디렉터리 없음. 보안상 양호")
            safety = True
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_14",command,result,is_safe,score)
        return info
    
    def W_15(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-ChildItem IIS:\AppPools | ForEach-Object { $n=$_.Name;$p=(Get-Item ('IIS:\\AppPools\\' + $n)).processModel;[PSCustomObject]@{ApplicationPool=$n;IdentityType=$p.identityType;UserName=if($p.identityType -eq 'SpecificUser'){$p.userName}else{$null}} } | Out-String" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        if "NetworkService" in response :
            print("웹 프로세서에 과도한 권한 할당. 보안상 취약")
            safety = False
            for line in response.splitlines() :
                if "NetworkService" in line :
                    line = line.strip()
                    result = line
        elif "SpecificUser" in response :
            print("웹 프로세서에 과도한 권한 할당. 보안상 취약")
            safety = False
            for line in response.splitlines() :
                if "SpecificUser" in line :
                        line = line.strip()
                        result = line
        elif "LocalSystem" in response :
            print("웹 프로세서에 과도한 권한 할당. 보안상 취약")
            safety = False
            for line in response.splitlines() :
                if "LocalSystem" in line :
                        line = line.strip()
                        result = line
        elif "Administrator" in response :
            print("웹 프로세서에 과도한 권한 할당. 보안상 취약")
            safety = False
            for line in response.splitlines() :
                if "Administrator" in line :
                        line = line.strip()
                        result = line
        else :
            print("웹 프로세서 권한 설정 양호함. 보안상 양호")
            safety = True
            for line in response.splitlines() :
                if "ApplicationPoolIdentity" in line :
                        line = line.strip()
                        result = line
                elif "LocalService" in line :
                        line = line.strip()
                        result = line
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_15",command,result,is_safe,score)
        return info
    
    def W_16(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-ChildItem IIS:\\Sites | ForEach-Object { $path = (Get-ItemProperty ('IIS:\\Sites\\' + $_.Name)).physicalPath; if ($path -and (Test-Path $path)) { Write-Output ('[inspection path] ' + $path); Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($_.Extension -eq '.lnk') } | Select-Object FullName, Attributes } }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "ReparsePoint" in response :
            print("IIS 사이트 내 심볼릭 링크 존재. 보안상 취약")
            safety = False
        elif ".lnk" in response :
            print("IIS 사이트 내 바로가기 파일 존재. 보안상 취약")
            safety = False
        else :
            print("IIS 사이트 내 링크 사용금지 설정 양호. 보안상 양호")
            safety = True
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_16",command,result,is_safe,score)
        return info
    
    def W_18(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-WebConfiguration -Filter 'system.webServer/handlers/add[@name=''ASPClassic'']' | Select-Object *" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
            if "verb" in line :
                line = line.strip()
                result = line
                value = line.split(':')[-1].strip()
                if value == "*" :
                    print(".asa 매핑 되어있고 모든 권한 설정. 보안상 취약")
                    safety = False
                else :
                    print(".asa 매핑 되어있지만 제한된 권한 설정. 보안상 양호")
                    safety = True
        if result == "결과 없음" :
            print(".asa 매핑 되어있지않음. 보안상 양호")
            safety = True
            result = (".asa 매핑 미설정")
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_18",command,result,is_safe,score)
        return info
    
    def W_19(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-ChildItem IIS:\Sites | ForEach-Object { $siteName = $_.Name; Write-Host ('===== Site:' + $siteName + '====='); $vdirs = Get-WebVirtualDirectory -Site $siteName; if ($vdirs) { $vdirs | Select-Object SiteName, Path, PhysicalPath | Format-Table -AutoSize } else { Write-Host 'No Web Virtual Directory' }; Write-Host '' }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        site = response.count("Site:")
        NoWeb = response.count("No Web Virtual Directory")
        
        if site == NoWeb :
            print("IIS 가상 디렉터리 없음. 보안상 양호")
            safety = True
        else :
            print("IIS 가상 디렉터리 존재. 보안상 취약")
            safety = False
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_19",command,result,is_safe,score)
        return info
    
    def W_20(self,host):
        command = """powershell -Command "$path='C:\inetpub\wwwroot'; Get-ChildItem -Path $path -Recurse -Force | ForEach-Object { $acl=Get-Acl $_.FullName; foreach ($ace in $acl.Access) { if ($ace.IdentityReference -eq 'Everyone') { [PSCustomObject]@{ Path=$_.FullName; AccessControlType=$ace.AccessControlType; FileSystemRights=$ace.FileSystemRights } } } }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "Path" in response :
            print("IIS 홈 디렉터리 내 Everyone 권한 존재. 보안상 취약")
            safety = False
        else :
            print("IIS 홈 디렉터리 내 Everyone 권한 없음. 보안상 양호")
            safety = True
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_20",command,result,is_safe,score)
        return info

    #def W_21(self,host):
        command = """powershell -Command "$vulnerableExtensions=@('.htr','.idc','.stm','.shtm','.shtml','.printer','.htw','.ida','.idq'); Get-ChildItem IIS:\Sites | ForEach-Object { $site=$_.Name; $out = '===Site: ' + $site + '===' + [Environment]::NewLine; $h=Get-WebConfigurationProperty -PSPath ('IIS:\\Sites\\' + $site) -Filter 'system.webServer/handlers' -Name '.'; $f=$false; $vulnerableExtensions | ForEach-Object { $ext=$_; $m=$h | Where-Object { $_.Path -like ('*' + $ext) }; if ($m) { $f=$true; $m | ForEach-Object { $out += 'Vulnerable Mapping: extension ' + $ext + ', Handler: ' + $_.Name + ', Path: ' + $_.Path + [Environment]::NewLine } } }; if (-not $f) { $out += 'No Vulnerable Mapping' + [Environment]::NewLine }; Write-Output $out }" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        print(response)
        result = response
        
        site = response.count("Site:")
        NoMap = response.count("No Vulnerable Mapping")
        
        if site == NoMap :
            print("IIS 취약한 맵핑 없음. 보안상 양호")
            safety = True
        else :
            print("IIS 취약한 맵핑 존재. 보안상 취약")
            safety = False
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_21",command,result,is_safe,score)
        return info

    def W_22(self,host):
        command = """powershell -Command "(Get-ItemProperty 'HKLM:\Software\Microsoft\InetStp').VersionString; $reg='HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters'; $v=Get-ItemProperty -Path $reg -Name 'SSIEnableCmdDirective' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SSIEnableCmdDirective -ErrorAction SilentlyContinue; if($v -eq 1){Write-Host 'Vulnerability: Exec Function Allowed (SSIEnableCmdDirective = 1)'}else{Write-Host 'Good: Exec Function Denied (SSIEnableCmdDirective = 0)'}" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
            if "Version" in line :
                line = line.strip()
                result = line
                value = float(line.split(' ')[-1].strip())
                if value >= 6 :
                    print("IIS 버전 6.0 이상. 보안상 양호")
                    safety = True
                else :
                    for line in response.splitlines() :
                        if "Exec Function" in line :
                            if "Denied" in line :
                                print("Exec 기능 차단됨. 보안상 양호")
                                safety = True
                                result = line
                            else :
                                print("Exec 기능 허용됨. 보안상 취약")
                                safety = False
                                result = line
        
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_22",command,result,is_safe,score)
        return info

    def W_23(self,host):
        command = """powershell -Command "$svc=Get-Service W3SVC -ErrorAction SilentlyContinue; if(!$svc){Write-Host 'No IIS'}elseif($svc.Status -eq 'Stopped'){Write-Host 'IIS Stopped'}else{Write-Host 'IIS Running'}; $r='HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters'; $d=(Get-ItemProperty -Path $r -Name DisableWebDAV -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWebDAV -ErrorAction SilentlyContinue); if($d -eq 1){Write-Host 'Registry Setting Good: DisableWebDAV = 1'}elseif($d -eq 0){Write-Host 'Registry Setting Vulnerability: DisableWebDAV = 0'}else{Write-Host 'No Registry Setting'}; $f=Get-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue; if($f -and $f.Installed){Write-Host 'IIS WebDAV Function Installed (Vulnerability)'}else{Write-Host 'IIS WebDAV Functing Not Installed (Good)'}" """
        is_safe = False
        safety = False
        safety1 = False
        safety2 = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "No IIS" in response :
            print("IIS 서비스 없음. 보안상 양호")
            safety = True
        elif "IIS Stopped" in response :
            print("IIS 중지. 보안상 양호")
            safety = True
        elif "IIS Running" in response :
            print("IIS 실행중. 취약 가능성 존재")
            safety = False
        if "Registry Setting Good" in response :
            print("레지스트리 설정 양호. 보안상 양호")
            safety1 = True
        elif "Registry Setting Vulnerability" in response :
            print("레지스트리 설정 취약. 보안상 취약")
            safety1 = False
        elif "No Registry Setting" in response :
            print("레지스트리 설정 없음. 취약 가능성 존재")
            safety1 = False
        if "IIS WebDAV Function Installed" in response :
            print("IIS WebDAV 기능 설치됨. 보안상 취약")
            safety2 = False
        elif "IIS WebDAV Functing Not Installed" in response :
            print("IIS WebDAV 기능 미설치. 보안상 양호")
            safety2 = True
        
        if safety == False and safety == safety1 and safety1 == safety2 :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        else :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_23",command,result,is_safe,score)
        return info

    def W_24(self,host):
        command = """powershell -Command "Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | Select-Object Description, TcpipNetbiosOptions" """
        is_safe = False
        safety = False
        evi = True
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
            line = line.strip()
            value = line.split(' ')[-1].strip()
            if value == "0" :
                print("NetBios 바인딩 Default. 취약 가능성 존재")
                safety = False
                result = line
                evi = False
            elif value == "1" :
                print("NetBios 바인딩 활성화. 보안상 취약")
                safety = False
                result = line
                evi = False
            elif value == "2" :
                print("NetBios 바인딩 비활성화. 보안상 양호")
                safety = True
                result = line
            
        if safety == True and evi == True:
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_24",command,result,is_safe,score)
        return info

    def W_25(self,host):
        command = """powershell -Command "Get-Service | Where-Object { $_.Name -like '*ftp*' -or $_.DisplayName -like '*ftp*' }" """
        is_safe = False
        safety = False
        evi = True
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        
        for line in response.splitlines() :
            if "ftp" in line or "FTP" in line :
                line = line.strip()
                value = line.split(' ')[0].strip()
                if value == "Running" :
                    print("FTP 서비스 활성화. 보안상 취약")
                    safety = False
                    result = line
                    evi = False
                else :
                    print("FTP 서비스 비활성화. 보안상 양호")
                    safety = True
                    result = line
            
        if safety == True and evi == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_25",command,result,is_safe,score)
        return info

    def W_26(self,host):
        command = """powershell -Command "$ftpPath='C:\\inetpub\\ftproot'; if(Test-Path $ftpPath){$acl=Get-Acl $ftpPath; $hasEveryone=$false; foreach($entry in $acl.Access){if($entry.IdentityReference -eq 'Everyone'){$hasEveryone=$true; Write-Host ($ftpPath + ': Everyone Authority Exists.' + $entry.FileSystemRights)}}; if(-not $hasEveryone){Write-Host ($ftpPath + ': No Everyone Authority.')}}" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "Everyone Authority Exists" in response :
            print("FTP 홈 디렉터리 내 Everyone 권한 존재. 보안상 취약")
            safety = False
        else :
            print("FTP 홈 디렉터리 내 Everyone 권한 없음. 보안상 양호")
            safety = True
            
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_26",command,result,is_safe,score)
        return info

    def W_27(self,host):
        command = """powershell -Command "Import-Module WebAdministration; Get-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -PSPath 'IIS:\' -Name * | Select-Object PSPath, enabled" """
        is_safe = False
        safety = False
        result = "결과 없음"
        score = 0
        time = 10
        
        response = util.para_connect(host,command,time)
        result = response
        
        if "True" in response :
            print("FTP 서비스 Anonymous 인증 허용. 보안상 취약")
            safety = False
        elif "False" in response:
            print("FTP 서비스 Anonymous 인증 차단. 보안상 양호")
            safety = True
        else :
            print("FTP 서비스 Anonymous 인증 설정 없음. 보안상 양호")
            safety = True
            
        if safety == True :
            print("검사 결과 보안상 양호")
            is_safe = True
            score = 3
        else :
            print("검사 결과 보안상 취약")
            is_safe = False
            score = 0
        
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_27",command,result,is_safe,score)
        return info

    def W_30(self, host):
        # 1. IIS 설치 여부
        command1 = 'powershell -Command "(Get-WindowsFeature Web-Server).Installed"'
        # 2. OS 버전 및 서비스팩 확인 (Windows 2000 SP4 이상 또는 2003 SP2 이상, 혹은 2008,2012,2016,2019,2022)
        command2 = (
            'powershell -Command "$os=(Get-CimInstance Win32_OperatingSystem); '
            'Write-Output \"$($os.Caption)|$($os.ServicePackMajorVersion)\""'
        )
        # 3. MSADC 가상 디렉토리 존재 여부 (IIS 설치된 경우만 확인)
        command3 = (
            'powershell -Command "Import-Module WebAdministration -ErrorAction SilentlyContinue; '
            '$msadc=(Get-WebVirtualDirectory -Site \'Default Web Site\' -ErrorAction SilentlyContinue | Where-Object Name -eq \'MSADC\').Count; '
            'Write-Output $msadc"'
        )
        # 4. 레지스트리 값 존재 여부 확인
        command4 = (
            'powershell -Command "$regs=@('
            '\'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters\\ADCLaunch\\RDSServer.DataFactory\','
            '\'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters\\ADCLaunch\\AdvancedDataFactory\','
            '\'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters\\ADCLaunch\\VbBusObj.VbBusObjCls\''
            '); '
            '$exists=($regs | Where-Object { Test-Path $_ }).Count; '
            'Write-Output $exists"'
        )

        iis_installed_str = util.para_connect(host, command1, 5).strip()
        os_info = util.para_connect(host, command2, 5).strip()
        msadc_count_str = util.para_connect(host, command3, 5).strip()
        reg_count_str = util.para_connect(host, command4, 5).strip()

        iis_installed = (iis_installed_str.lower() == 'true')

        os_version = ''
        sp = 0
        if '|' in os_info:
            parts = os_info.split('|')
            if len(parts) == 2:
                os_version = parts[0]
                sp = int(parts[1]) if parts[1].isdigit() else 0

        msadc_count = int(msadc_count_str) if msadc_count_str.isdigit() else 0
        reg_count = int(reg_count_str) if reg_count_str.isdigit() else 0

        cond1 = not iis_installed
        cond2 = (
            ('2000' in os_version and sp >= 4) or
            ('2003' in os_version and sp >= 2) or
            any(ver in os_version for ver in ['2008', '2012', '2016', '2019', '2022'])
        )
        cond3 = (msadc_count == 0)
        cond4 = (reg_count == 0)

        is_safe = cond1 or cond2 or cond3 or cond4
        print("양호" if is_safe else "취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")

        command = f"{command1}\n{command2}\n{command3}\n{command4}"
        response = f"IIS Installed: {iis_installed_str}\nOS Info: {os_info}\nMSADC Count: {msadc_count_str}\nRegistry Count: {reg_count_str}"

        return Info(host.id, date, "W_30", command, response, is_safe, score)  

    def W_31(self,host):
        command = 'powershell -Command "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, ServicePackMinorVersion"'
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response

        if "Windows Server 2022" in result or "10.0.20348" in result:
            is_safe = True
            print("양호")
        else :
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_31",command,result,is_safe,score)
        return info

    def W_32(self, host):
        command = (
            'powershell -Command "'
            '$svc1 = Get-Service PMSAgent -ErrorAction SilentlyContinue; '
            '$svc2 = Get-Service PatchManagementAgent -ErrorAction SilentlyContinue; '
            '$pmsRunning = ($svc1 -and $svc1.Status -eq \'Running\' -and $svc1.StartType -eq \'Automatic\') -or '
            '($svc2 -and $svc2.Status -eq \'Running\' -and $svc2.StartType -eq \'Automatic\'); '
            '$latest = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; '
            '$days = if ($latest) { (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).Days } else { 9999 }; '
            'Write-Output "$pmsRunning;$days"'
            '"'
        )
        response = util.para_connect(host, command, 15).strip()
        lines = response.splitlines()
        pms_running = (lines[0].strip() == 'True') if len(lines) > 0 else False
        try:
            days = int(lines[1].strip()) if len(lines) > 1 else 9999
        except ValueError:
            days = 9999

        #PMS 작동 유무 / Hot fix 설치 1년 이내
        is_safe = pms_running and days <= 365

        print("양호" if is_safe else "취약")
        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_32", command, response, is_safe, score)

    def W_33(self,host):
        command = 'powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureVersion"'
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response

        # AntivirusEnabled가 True인지 확인
        enabled = "AntivirusEnabled" in result and "True" in result

        # 날짜 파싱 시도
        try:
            # 예: 2025-06-30 형식으로 날짜 찾기 (필요하면 시간 포함 포맷에 맞게 수정 가능)
            match = re.search(r'\d{4}-\d{2}-\d{2}', result)
            if match:
                date_str = match.group()
                sig_date = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
                days_diff = (datetime.date.today() - sig_date).days
            else:
                days_diff = 9999  # 날짜 못찾으면 매우 오래된 것으로 처리
        except:
            days_diff = 9999

        if enabled or days_diff <= 7:
            is_safe = True
            print("양호")
        else :
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_33",command,result,is_safe,score)
        return info

    def W_34(self, host):
        report_folder = r'C:\Reports'
        command = (
            f'powershell "if(!(Test-Path \'{report_folder}\')){{New-Item \'{report_folder}\' -ItemType Directory | Out-Null}}; '
            f'$d=(Get-Date).AddDays(-7); '
            f'$c=Get-ChildItem \'{report_folder}\' -Filter \'*.csv\' | ? {{$_.LastWriteTime -ge $d}}; '
            f'Write-Output $c.Count"'
        )
        response = util.para_connect(host, command, 10).strip()

        
        count = int(response)
        is_safe = (count > 0)
        print("양호" if is_safe else "취약")
        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_34", command, response, is_safe, score)

    def W_35(self,host):
        command = 'powershell -Command "Get-Service -Name RemoteRegistry | Select-Object Status, StartType"'
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response

        if "Stopped" in result:  
            is_safe = True
            print("양호")
        elif "Running" in result:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_35",command,result,is_safe,score)
        return info

    def W_36(self,host):
        command = 'powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled"'
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response

        if result.count("True") == 2:
            is_safe = True
            print("양호")
        else :
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_36",command,result,is_safe,score)
        return info

    def W_37(self,host):
        command = ('powershell -Command ''"$samPath = \'C:\\Windows\\System32\\config\\SAM\'; ''(Get-Acl $samPath).Access | Select-Object IdentityReference, FileSystemRights, AccessControlType | Out-String"')
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response
        
        if "Everyone" in result or "Users" in result or "Guests" in result:
            is_safe = False
            print("취약")
        elif ("NT AUTHORITY\\SYSTEM" in result and "FullControl" in result) and ("BUILTIN\\Administrators" in result and "FullControl" in result):
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_37",command,result,is_safe,score)
        return info

    def W_38(self,host):
        command = ('powershell -Command ''"Get-ItemProperty -Path \'HKCU:\\Control Panel\\Desktop\' | ''Select-Object ScreenSaveActive, ScreenSaveTimeOut, ScreenSaverIsSecure | Out-String"')
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response
        
        if ("ScreenSaveActive" in result and "1" in result) and ("ScreenSaveTimeOut" in result and "600" in result) and (" ScreenSaverIsSecure" in result and "1" in result):
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_38",command,result,is_safe,score)
        return info

    def W_39(self,host):
        command = """powershell -Command "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'ShutdownWithoutLogon' -ErrorAction SilentlyContinue).ShutdownWithoutLogon"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response
        
        if result == "0":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_39",command,result,is_safe,score)
        return info

    def W_40(self, host):
        command = (
            'powershell "secedit /export /areas USER_RIGHTS /cfg $env:TEMP\\sp.cfg > $null; '
            '$l=Get-Content $env:TEMP\\sp.cfg | Select-String SeRemoteShutdownPrivilege; '
            'Remove-Item $env:TEMP\\sp.cfg -EA SilentlyContinue; '
            'if ($l) { ($l -split \'=\')[1] }"'
        )
        response = util.para_connect(host, command, 10).strip()

        members = []
        if response:
            members = [m.strip().replace("*","") for m in response.split(',')]
        others = [m for m in members if m != 'Administrators']

        is_safe = (len(others) == 0)
        print("양호" if is_safe else "취약")
        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_40", command, response, is_safe, score)

    def W_41(self,host):
        command = """powershell -Command "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'CrashOnAuditFail' -ErrorAction SilentlyContinue).CrashOnAuditFail"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response.strip()
        
        if result == "0":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_41",command,result,is_safe,score)
        return info

    def W_42(self,host):
        command = """powershell -Command "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue).RestrictAnonymous"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response.strip()
        
        if result == "1":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_42",command,result,is_safe,score)
        return info

    def W_43(self, host):
        command = (
            'powershell "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\' '
            '-Name AutoAdminLogon -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoAdminLogon"'
        )
        response = util.para_connect(host, command, 10).strip()

        is_safe = (response != '1')
        print("양호" if is_safe else "취약")
        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_43", command, response, is_safe, score)

    def W_45(self, host):
        path = r'C:\Users\Public'
        command = f'powershell "(Get-Item \'{path}\').Attributes"'
        response = util.para_connect(host, command, 10).strip()

        is_safe = ('Encrypted' in response)
        print("양호" if is_safe else "취약")
        score = 3
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_45", command, response, is_safe, score)

    def W_46(self,host):
        command = """powershell -Command "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').EveryoneIncludesAnonymous"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response.strip()
        
        if result == "0":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_46",command,result,is_safe,score)
        return info

    def W_47(self, host):
        command = (
            'powershell "secedit /export /areas SECURITYPOLICY /cfg $env:TEMP\\lock.cfg > $null; '
            'Get-Content $env:TEMP\\lock.cfg | Select-String \'^LockoutDuration\' | % {($_ -split \'=\')[1]}; '
            'Get-Content $env:TEMP\\lock.cfg | Select-String \'^ResetLockoutCount\' | % {($_ -split \'=\')[1]}; '
            'Remove-Item $env:TEMP\\lock.cfg -EA SilentlyContinue"'
        )
        response = util.para_connect(host, command, 10).strip()

        lines = response.split('\n')
        try:
            lockout = int(lines[0])
            reset = int(lines[1])
        except:
            lockout = 0
            reset = 0
        is_safe = (lockout >= 60 and reset >= 60)
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_47", command, response, is_safe, score)

    def W_48(self, host):
        command = (
            'powershell "secedit /export /areas SECURITYPOLICY /cfg $env:TEMP\\pwd.cfg > $null; '
            'Get-Content $env:TEMP\\pwd.cfg | Select-String \'^PasswordComplexity\' | % {($_ -split \'=\')[1]}; '
            'Remove-Item $env:TEMP\\pwd.cfg -EA SilentlyContinue"'
        )
        response = util.para_connect(host, command, 10).strip()

        is_safe = (response == '1')
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_48", command, response, is_safe, score)

    def W_49(self, host):
        command = (
            'powershell "secedit /export /areas SECURITYPOLICY /cfg $env:TEMP\\pwd.cfg > $null; '
            'Get-Content $env:TEMP\\pwd.cfg | Select-String \'^MinimumPasswordLength\' | % {($_ -split \'=\')[1]}; '
            'Remove-Item $env:TEMP\\pwd.cfg -EA SilentlyContinue"'
        )
        response = util.para_connect(host, command, 10).strip()

        
        length = int(response)
        is_safe = (length >= 8)
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_49", command, response, is_safe, score)

    def W_50(self, host):
        command = (
            'powershell "secedit /export /areas SECURITYPOLICY /cfg $env:TEMP\\pwd.cfg > $null; '
            'Get-Content $env:TEMP\\pwd.cfg | Select-String \'^MaximumPasswordAge\' | % {($_ -split \'=\')[1]}; '
            'Remove-Item $env:TEMP\\pwd.cfg -EA SilentlyContinue"'
        )
        response = util.para_connect(host, command, 10).strip()

        days = int(response)
        is_safe = (0 < days <= 90)
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_50", command, response, is_safe, score)

    def W_51(self, host):
        command = (
            'powershell "secedit /export /areas SECURITYPOLICY /cfg $env:TEMP\\pwd.cfg > $null; '
            'Get-Content $env:TEMP\\pwd.cfg | Select-String \'^MinimumPasswordAge\' | % {($_ -split \'=\')[1]}; '
            'Remove-Item $env:TEMP\\pwd.cfg -EA SilentlyContinue"'
        )
        response = util.para_connect(host, command, 10).strip()

        days = int(response)
        
        is_safe = (days > 0)
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_51", command, response, is_safe, score)

    def W_52(self,host):
        command = """powershell -Command "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').DontDisplayLastUserName"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response.strip()
        
        if result == "1":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")

        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_52",command,result,is_safe,score)
        return info

    def W_53(self, host):
        command = (
            'powershell "secedit /export /areas USER_RIGHTS /cfg $env:TEMP\\sp.cfg > $null; '
            '$l=Get-Content $env:TEMP\\sp.cfg | Select-String SeInteractiveLogonRight; '
            'Remove-Item $env:TEMP\\sp.cfg -EA SilentlyContinue; '
            'if ($l) { ($l -split \'=\')[1] }"'
        )
        response = util.para_connect(host, command, 10).strip()

        members = []
        if response:
            members = response.split(',')
        #S-1-5-32-544 = Administrator , S-1-5-32-568 = IUSR(Group) , S-1-5-17 = IUSR
        unauthorized = [m for m in members if m != '*S-1-5-32-544' and m != '*S-1-5-32-568' and m != '*S-1-5-17' ]
        is_safe = (len(unauthorized) == 0)
        print("양호" if is_safe else "취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        return Info(host.id, date, "W_53", command, response, is_safe, score)

    def W_54(self,host):
        command = """powershell -Command "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'AllowAnonymousNameTranslation' -ErrorAction SilentlyContinue).AllowAnonymousNameTranslation"""
        score = 0 
        is_safe = False
        time = 10

        response = util.para_connect(host,command,time)
        result = response.strip()
        
        if result == "0" or result == "":
            is_safe = True
            print("양호")
        else:
            is_safe = False
            print("취약")
        score = 2
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id,date,"W_54",command,result,is_safe,score)
        return info

    def W_55(self, host):
        command = 'powershell "Get-ADDefaultDomainPasswordPolicy | Select-Object -ExpandProperty PasswordHistoryCount"'
        is_safe = False
        score = 0
        # 명령어가 여러줄일 때 시간을 늘려준다.
        time = 10
        
        response = util.para_connect(host, command, time)
        result = response

        # 최근 암호 기억이 4개 이상으로 설정되어 있는지 확인함
        if result.isdigit() and int(result) >= 4:
            is_safe = True
            score = 3
            print("양호")    
        else:
            is_safe = False
            score = 3
            print("취약")

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "W_55", command, result, is_safe, score)
        return info
    
    def W_56(self, host):
        command = 'powershell "Get-ItemProperty -Path \\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" -Name LimitBlankPasswordUse"'
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response

        # LimitBlankPasswordUse 값이 1이면 양호, 아니면 취약
        if "LimitBlankPasswordUse" in result and "1" in result:
            is_safe = True
            score = 3
            print("양호")
        else:
            is_safe = False
            score = 0
            print("취약")
            
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "W_56", command, result, is_safe, score)
        return info

    def W_57(self, host):
        command = 'powershell "Get-LocalGroupMember -Group \\"Remote Desktop Users\\""'
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response

        # 원격 접속이 가능한 사용자 계정 탐색 : 없을 경우 양호
        if result.strip() =="":
            is_safe = True
            score = 3
            print("양호")
        else:
            is_safe = False
            score = 0
            print("취약")

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "W_57", command, result, is_safe, score)
        return info

    def W_58(self, host):
        command = 'powershell "Get-ItemProperty -Path \\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\" -Name MinEncryptionLevel"'
        is_safe = False
        score = 0
        time = 10

        response = util.para_connect(host, command, time)
        result = response

        if result and "MinEncryptionLevel" in result:
            lines = result.splitlines()
            for line in lines:
                if "MinEncryptionLevel" in line:
                    val = line.split(":")[1].strip()
                    if val.isdigit() and int(val) >= 2:
                        is_safe = True
                        score = 3
                        print("양호")   # 암호화 수준 중간 이상
                    else:
                        is_safe = False
                        score = 0
                        print("취약")   # 암호화 수준 낮음
        else:
            # 값 없으면 터미널 서비스 미사용으로 양호 판단
            is_safe = True
            score = 3
            print("양호")

        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "W_58", command, result, is_safe, score)
        return info


        date = datetime.datetime.now().strftime("%Y-%m-%d")
        info = Info(host.id, date, "W_58", command, result, is_safe, score)
        return info

    def W_60(self,host):
        command = 'powershell "Get-Service -Name snmp -ErrorAction SilentlyContinue | Select-Object Status"'  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        result = response
        # snmp 가 실행 중인지 여부를 탐색
        if result and "Running" in result:
                is_safe = False
                score = 0
                print("취약")
        else:
                is_safe = True
                score = 3
                print("양호")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_60",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_61(self,host):
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities\' "'  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "public" not in result and "private" not in result:
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_61",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_62(self,host):
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers\' -ErrorAction SilentlyContinue"'
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
         # 전체 허용 IP(0.0.0.0 또는 *)가 포함되어 있으면 취약
        if "0.0.0.0" not in result and "*" not in result and result.strip() not in ("", "{}"):
            is_safe = True
            score = 3
            print("양호")
        else :
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_62",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_63(self,host):
        command = 'powershell "Get-DnsServerZone | Select-Object ZoneName, DynamicUpdate"'
        is_safe = False
        score = 0
        time = 10

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "None" in result:
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_63",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_65(self,host): ### 장담하기 어려움
        command = 'powershell "(Get-Service Telnet -EA SilentlyContinue).Status -ne \'Running\' -or (Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\TelnetServer\\1.0\' -Name NTLM -EA SilentlyContinue).NTLM -eq 1"'
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "True" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_65",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_66(self,host):
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\ODBC\\ODBC.INI\\ODBC Data Sources\'"'  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        response = util.para_connect(host,command,time)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "{}" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_66",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_67(self,host): #### 많이 애매하다.
        command = command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\' -Name MaxIdleTime -ErrorAction SilentlyContinue"'  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "MaxIdleTime" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = True
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_67",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_68(self,host):
        command = 'powershell -Command "Get-ScheduledTask | '
        'Get-ScheduledTaskInfo | ForEach-Object {($_.TaskName)}; '
        'Get-ScheduledTask | ForEach-Object {($_.Actions)}"'
    
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        ## 의심스러운 명령어 리스트
        suspicious_keywords = ["wget", "curl", "powershell -enc", "cmd.exe", "nc.exe", "ftp", "bitsadmin", "iex"]
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if result:
            lowered = result.lower()
            if any(keyword in lowered for keyword in suspicious_keywords):
                is_safe = False
                score = 0
                print("취약")
            else:
                is_safe = True
                score = 3
                print("양호")
        else:
            is_safe = True
            score = 3
            print("양호")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_68",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info
    
    def W_69(self,host):   #### 애게 맞나???
        command = 'powershell -Command "Get-WinEvent -ListLog Application, System, Security | '
        'Select-Object LogName, IsEnabled, Retention, LogMode, MaximumSizeInBytes"'
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response

        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if result and all(log in result for log in ['Application', 'System', 'Security']):
            true_count = result.lower().count('true')
            if true_count >= 3:
                is_safe = True
                score = 3
                print("양호")
            
            else:
                is_safe = False
                score = 0
                print("취약")
        
        else:
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_69",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info    

    def W_70(self,host): ### 길어도 무지 길다
        command = r'''powershell -Command "$isSafe=$true;foreach($l in 'Application','System','Security'){$c=Get-WinEvent -ListLog $l;if(!($c.Retention.ToString() -eq 'RetainAsNeeded' -and $c.LogMaxSize -ge 10485760)){$isSafe=$false;break}};if($isSafe){'SAFE_LOGS'}else{'UNSAFE_LOGS]'}"'''
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 30

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_LOGS" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = True
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_70",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_71(self,host):
        command = r'''powershell -Command "Get-Acl 'C:\Windows\System32\winevt\Logs' | Select-Object -ExpandProperty Access | Format-List IdentityReference"'''  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "Everyone" not in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = True
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_71",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_72(self,host):
        command = r'''powershell -Command "$Tcpip=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -ErrorAction SilentlyContinue; $Netbt=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters -ErrorAction SilentlyContinue; if ($Tcpip.SynAttackProtect -ge 1 -and $Tcpip.EnableDeadGWDetect -eq 0 -and $Tcpip.KeepAliveTime -eq 300000 -and $Netbt.NoNameReleaseOnDemand -eq 1) { Write-Output 'SAFE' } else { Write-Output 'UNSAFE' }"'''
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if result and "SAFE" in result:
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_72",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_73(self,host):
        command = r'''powershell -Command "$val=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows NT\Printers -Name DisallowUserInstall -ErrorAction SilentlyContinue).DisallowUserInstall; if($val -eq 1){'SAFE'}else{'UNSAFE'}"'''
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_73",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_74(self,host):
        command = r"powershell -Command \"$r='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services';$s=$true;try{$f=(gpv $r fResetBroken -ea 0);$m=(gpv $r MaxIdleTime -ea 0);if(!($f-eq 1-and$m-eq 900000000)){$s=$false}}catch{$s=$false};if($s){'SAFE_TIMEOUT'}else{'[UNSAFE_TIMEOUT]'}\""  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_TIMEOUT" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_74",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_75(self,host):
        command = r"powershell -Command \"$r='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';$c=(gpv $r LegalNoticeCaption -ea 0);$t=(gpv $r LegalNoticeText -ea 0);if(![string]::IsNullOrWhiteSpace($c)-and![string]::IsNullOrWhiteSpace($t)){'SAFE_MESSAGE'}else{'UNSAFE_MESSAGE'}\""  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_MESSAGE" in result :
            is_safe = True
            score = 3
            print("양호")

        else :
            is_safe = 0
            print("no")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_75",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_76(self,host):
        command = r'''powershell -Command "$bp='C:\Users';$e=@('All Users','Default','Default User','Public','desktop.ini');$s=$true;gci $bp -di|?{$e-notc $_.Name}|%{try{$a=(gac $_.FullName).Access|?{$_.IdentityReference-eq'Everyone'};if($a){$s=$false;break}}catch{$s=$false;break}};if($s){'SAFE_HOME'}else{'UNSAFE_HOME'}"'''  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 30

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_HOME" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_76",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_77(self,host):
        command = r"powershell -Command \"$r='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa';$l=(gpv $r LmCompatibilityLevel -ea 0);if($l-eq 5){'SAFE_LEVEL'}elseif($l-ge 0-and$l-le 4){'UNSAFE_LEVEL'}else{'UNSAFE_LEVEL'}\""
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_LEVEL" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_77",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_78(self,host):
        command = r"powershell -Command \"$r='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters';$s1=(gpv $r RequireSignOrSeal -ea 0);$s2=(gpv $r SealSecureChannel -ea 0);$s3=(gpv $r SignSecureChannel -ea 0);if($s1-eq 1-and$s2-eq 1-and$s3-eq 1){'[SAFE_CHANNEL]'}else{'[UNSAFE_CHANNEL]'}\""
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_CHANNEL" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = True
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_78",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_79(self,host):
        command = r'''powershell -Command "$isSafe=$true;Get-Volume|Where-Object{$_.FileSystem-ne$null}|ForEach-Object{if($_.FileSystem-ne'NTFS'){$isSafe=$false;break}};if($isSafe){'SAFE_FD'}else{'UNSAFE_FD'}"'''
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 15

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_FD" in result :
            is_safe = True
            score = 3
            print("양호")
        else : 
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_79",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_80(self,host):
        command = r"powershell -Command \"$s=$true;$d=(gpv HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters DisablePasswordChange -ea 0);if($d-eq 1){$s=$false};if($s){try{$p=Get-ADDefaultDomainPasswordPolicy -ea Stop;$m=$p.MaxPasswordAge.Days;if($m-gt 90){$s=$false}}catch{}};if($s){'SAFE_PASSWORD'}else{'UNSAFE_PASSWORD'}\""  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "UNSAFE_PASSWORD" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_80",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

    def W_81(self,host):
        command = r"powershell -Command \"$s=$true;$k=@('ftp','curl','powershell','bypass','.vbs','.ps1','bitsadmin','schtasks','cmd /c','reg add','http');Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue|%{if($_.Command){$c=$_.Command;foreach($kw in $k){if($c-match$kw){$s=$false;break}}};if(!$s){break}};if($s){'SAFE_START'}else{'UNSAFE_START'}\""  
        is_safe = False
        score = 0

        #명령어가 여러 줄일 때만 수정 필요
        time = 30

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
        if "SAFE_START" in result :
            is_safe = True
            score = 3
            print("양호")
        else :
            is_safe = False
            score = 0
            print("취약")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_81",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

windows = Windows()

# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"window","window22","172.16.10.4","Administrator","asd123!@")

#info = windows(hosta)
#print(vars(info))

