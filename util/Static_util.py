import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pymysql
import paramiko
import netmiko
import time

class Static_util:
    def query(self,cmd,params):
        # db.txt 파일에서 정보 읽기
        with open(__file__+"/../db.txt", "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]
            ip, port, id, pw = lines[0], lines[1], lines[2], lines[3]
        # DB 연결
        db = pymysql.connect(host=ip, port=int(port), user=id, passwd=pw, charset='utf8', db="guideline")
        cur = db.cursor()
        if params:
            cur.execute(cmd,params)
        else :
            cur.execute(cmd)
        rows = []
        if "SELECT" in cmd or "SHOW" in cmd:
            rows = cur.fetchall()
        elif "INSERT" in cmd:
            db.commit()
            rows = ["query ok"]
        db.close()
        return list(rows)
    
    def squery(self,host,cmd):
        # host에서 정보 얻기
        ip = host.ip
        port = 3306
        id = host.username
        pw = host.password

        # DB 연결
        db = pymysql.connect(host=ip, port=int(port), user=id, passwd=pw, charset='utf8mb4', db="guideline")
        cur = db.cursor()
        cur.execute(cmd)
        rows = []
        if "SELECT" in cmd or "SHOW" in cmd:
            rows = cur.fetchall()
        elif "INSERT" in cmd:
            db.commit()
            rows = ["query ok"]
        db.close()
        return list(rows)

    #def para_connect(self,host,cmd,time1) :
        cli = paramiko.SSHClient() # ssh 클라이언트 인스턴스를 생성 ---> cli 객체
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy)  # 접속할 때 에러 메시지 처리 
        try:
            cli.connect(host.ip,username=host.username,password=host.password) #ip,username,password로 ssh 연결
        except Exception as e:
            print(e)

        result = ""
        cmd_list = cmd.strip().split("\n")
        
        # 명령어가 한 줄이라면 exec으로 실행한다. -> 대기시간 필요 x
        if len(cmd_list) == 1:
            stdin,stdout,stderr = cli.exec_command(cmd_list[0])
            for a in stdout:
                result += a
        # 명령어가 여러 줄이라면 invoke_shell로 실행한다. -> 대기시간 입력 필요 o
        else :
            connection = cli.invoke_shell()
            for cmd_item in cmd_list:
                connection.send(cmd_item + "\n")
                time.sleep(time1)
                result += connection.recv(65535).decode('utf-8')
                result += "\n"
        cli.close()
        
        return result
    
    def para_connect(self, host, cmd, time1):
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            cli.connect(host.ip, username=host.username, password=host.password)
        except Exception as e:
            print(f"[ERROR] SSH 연결 실패: {e}")
            return "[ERROR] SSH 연결 실패"

        result = ""
        cmd_list = cmd.strip().split("\n")

        try:
            if len(cmd_list) == 1:
                stdin, stdout, stderr = cli.exec_command(cmd_list[0])
                for a in stdout:
                    result += a
            else:
                connection = cli.invoke_shell()
                for cmd_item in cmd_list:
                    connection.send(cmd_item + "\n")
                    time.sleep(time1)
                    result += connection.recv(65535).decode('utf-8')
                    result += "\n"
        except Exception as e:
            print(f"[ERROR] 명령 실행 실패: {e}")
            result += f"\n[ERROR] 명령 실행 실패: {e}"
        finally:
            cli.close()

        return result


    #6. 명령어 전달 및 결과값 저장 def net_connect(user) return result
    def net_connect (self,host, cmd,time1):
        net_connect = netmiko.ConnectHandler(device_type="cisco_ios", ip=host.ip,username=host.username,password=host.password,timeout=30) # ssh 연결
        net_connect.enable() #관리자 모드 실행
        cmd_list = cmd.split("\n")
        #명령어가 한줄이라면 privilege mode에서 실행
        if len(cmd_list) == 1 :
            result =net_connect.send_command(cmd_list[0])
        #명령어가 여러 줄이라면 config mode에서 실행
        else :
            for a in cmd_list:
                result += net_connect.send_config_set(a)
                time.sleep(time1)
        net_connect.disconnect()

        return result 

util = Static_util()

#test 
#from vo.Host import Host
#print(__file__)
#hosta = Host(1,"unix","rocky17","172.16.17.100","root","asd123!@")
#resulta = util.query("SELECT * FROM host")
#print(resulta)
#print(hosta.id)
#result = util.para_connect(hosta,"ip a",None)
#print(result)





