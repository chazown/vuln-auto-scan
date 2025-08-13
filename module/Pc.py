import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime



class Pc:
    def PC_01(host):
        command = "ip a"
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
        if "ens160" in result :
            is_safe = True
            score = 3
        else :
            print("no")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
        info = Info(host.id,date,"W_01",command,result,is_safe,score)
        #5. 정보 객체 반환
        return info

pc = Pc()

# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"unix","rocky17","172.16.17.100","root","asd123!@")

#info = Pc.PC_01(hosta)
#print(vars(info))

