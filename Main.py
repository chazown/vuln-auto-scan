from vo.Host import Host
from vo.Info import Info
from util.Static_util import util
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from module.Cloud import cloud
from module.Db import db
from module.Network import network
from module.Pc import pc
from module.Security import security
from module.Unix import unix
from module.Web import web
from module.Windows import windows



class Main :
    def __init__(self):
        #category_list : unix, windows, security, network, pc, db, web, cloud 각 영역의 호스트 리스트가 담겨 있는 리스트
        self.category_list = [[],[],[],[],[],[],[],[]]
        self.category_dict = {"unix":unix,"windows":windows,"security":security,"network":network, "pc":pc, "db":db, "web":web, "cloud":cloud }
        self.run()

    # db 정보를 바탕으로 category_list에 값을 채운다.
    def getHost(self):
        # db에서 host 테이블 정보 받아오기
        raws = util.query("SELECT id,category,hostname,ip,username,password FROM host",{})
        #영역별로 분류해서 category_list 안의 리스트에 담기
        
        print("=== [DB에서 읽은 host 데이터] ===")
        for i in raws:
            print(i)

        for i in raws:
            host = Host(i[0],i[1],i[2],i[3],i[4],i[5])
            if i[1] == "unix":
                self.category_list[0].append(host)
            elif i[1] == "windows":
                self.category_list[1].append(host)
            elif i[1] == "security":
                self.category_list[2].append(host)
            elif i[1] == "network":
                self.category_list[3].append(host)
            elif i[1] == "pc":
                self.category_list[4].append(host)
            elif i[1] == "db":
                self.category_list[5].append(host)
            elif i[1] == "web":
                self.category_list[6].append(host)
            elif i[1] == "cloud":
                self.category_list[7].append(host)
            else: 
                print("there is something wrong")
        #print(self.category_list)

    # category_list를 for문 돌려서 get_category를 호출하는 함수 - 카테고리 n
    def multi_category(self):
        with ThreadPoolExecutor(max_workers=1) as executor3:
            for host_list in self.category_list:
                executor3.submit(self.get_category,host_list)
                
    # category 값 정하고, meth_list 값 정해서, multi_host 호출하는 함수
    def get_category(self,host_list):
        #카테고리 특정 짓기
        category = ""
        # host_list의 첫번째 값에서 category 뽑아내기
        try:
            category = host_list[0].category
        except IndexError:
            print("empty list.")
        #print(category)

        #str 타입의 데이터를 바탕으로 category_dict에 넣어서 class 타입으로 바꾸기
        try:
            category = self.category_dict[category]
        except KeyError:
            print("no key")
        
        #한 영역의 점검함수 이름을 담는 리스트
        meth_list = []
        
        #특정 class에서 함수 목록 가져와서 meth_list 채우기
        for method_name in dir(category):
            if callable(getattr(category, method_name)) and method_name.count("_") == 1:
                meth_list.append(method_name)
        # multi_host 호출
        self.multi_host(category,host_list,meth_list)
    
    # host_list를 for문 돌려서 multi_meth()를 병렬실행하는 함수 - 카테고리 1
    def multi_host(self,category,host_list,meth_list):
        #host_list에 for문 돌려서 호출
        with ThreadPoolExecutor(max_workers=5) as executor2:
            for host in host_list:
                executor2.submit(self.multi_meth,category,host,meth_list)

    # meth_list를 for문 돌려서 call_meth()를 병렬실행하는 함수 - 호스트 1
    def multi_meth(self,category,host,meth_list):
        #meth_list에 for문 돌려서 호출
        with ThreadPoolExecutor(max_workers=5) as executor1:
            for meth in meth_list:
                executor1.submit(self.call_meth,category,host,meth) 

    # 점검 함수 하나를 호출해서 실행하고 결과값을 db에 저장하는 함수 - 함수 1
    def call_meth(self,category,host,meth):
        print( meth+"를 시작합니다.")
        info = getattr(category,meth)(host)
        #print(info)
        try:
            cmd = """INSERT INTO info(id,date,content,command,result,is_safe,score) VALUES (%s, %s, %s, %s, %s,%s ,%s)"""
            is_safe_val = 1 if info.is_safe else 0
            para = (info.id, info.date, info.content, info.command, info.result,is_safe_val , info.score)
            util.query(cmd,para)
        except Exception as e:
            print("쿼리 실행중 에러가 발생했습니다.")
            print("에러 메시지:", e)
        finally:
            print( meth+"가 끝났습니다.")
        

    # main 실행 함수
    def run(self):
        self.getHost()
#        for host_list in self.category_list:
#            print("--------------------------------------------")
#            try:
#                print("category = %s"%(host_list[0].category))
#            except IndexError:
#                print("no")
#            for host in host_list:
#                print(host)
        self.multi_category()
        
#Test 
main = Main()


