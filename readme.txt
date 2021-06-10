MOGUL_모굴

<<<사용모듈>>>
from scapy.all import*
import string
import random
import urllib.request
from time import time
import asyncio
import aiohttp
import requests
import copy
from bs4 import BeautifulSoup, SoupStrainer
from functools import partial
import sys
from urllib.request import build_opener, HTTPCookieProcessor
import http.cookiejar as cookielib
from html.parser import HTMLParser
from urllib.parse import urlencode
import errno
import time
from urllib.parse import urlparse

*별도 설치 필요

<<<주의>>>
1.subdomains파일 삭제시 기능 모두 사용 불가

2.2차 수정 금지

3.악용하던가 말든가 내 알바아님
  사용시 발생하는 책임은 니 책임

4.반드시 readme.txt,subdomain.txt,MOGUL.py,ddos.py 모두 묶어서 배포

5.생각나면 적어서 다시 배포

<<<사용법>>>
1.fuzz #buff#수동형
>fuzz <ip> <port> <buff>
ex) fuzz 127.0.0.1 80 65535

2.sniff1 #패킷 전체 표시
>snf1 <any option> <any option> <any option>
ex) snf1 0 0 0

3.sniff2 #ip만표시
>snf2 <any option> <any option> <any option>
ex) snf2 0 0 0

4.ipconfig #나의 ip&컴터이름 표시
>ipcg <any option> <any option> <any option>
ex) ipcg 0 0 0

5.port scan #스캔가능한 포트
>>>[0,1,5,7,9,11,13,15,17,18,19,20,21,22,23,25,28,37,42,43,47,49,51,52,53,54,56,58,
61,67,68,69,70,71,72,73,74,79,80,81,82,83,88,90,95,101,102,104,105,107,108,109,
110,113,115,117,118,119,123,126,135,147,138,139,143,152,153,156,158,161,162,170,177,
179,194,199,201,209,210,213,218,220,225,226,227,228,229,230,231,232,233,234,
235,236,237,238,239,240,241,249,250,251,252,253,254,255,259,262,264,280,
300,308,311,319,320,350,351,383,369,384,399,401,427,434,443,444,445,464,
465,500,510,514,524,540,548,631,636,655,660,666,981,990,992,993,995,1311,
1513,2083,3306,3389,5228,5353,8008,8080,12000]
>pscn <ip> <tcp/all> <finish time os/off>

<tcp/all>
"-t" = tcp
"-a" = all (udp/tcp)

<finish time os/off>
"-f" = on
else = off

ex) pscn 127.0.0.1 -t -f

6.analyze url #웹 응답분석
>anurl <any option> <any option> <any option>
ex) anurl 0 0 0
>>>그러면 별도의 input메세지 등장

7.webscan1 #웹 정보탐색
>webscn1 <any option> <any option> <any option>
ex) webscn1 0 0 0
>>>그러면 별도의 input메세지 등장

8..webscan2 #웹 정보탐색
>webscn2 <any option> <any option> <any option>
ex) webscn2 0 0 0
>>>그러면 별도의 input메세지 등장

9.shellcode #효과_미미_주의#비추천#사실#될지#모름
>shell <ip> <port> <any option>
>>>그러면 별도의 input메세지 등장

10.sql injection #sql주입
>sqli <any option> <any option> <any option>
>>>그러면 별도의 input메세지 등장하는데 "Url like"에는 "https://www.29cm.co.kr/"처럼 원본 url을,
"Post like"에는 "https://www.29cm.co.kr/member/login"처럼 sql을 주입할 url을 써주면됨

11.admin #관리자 페이지 찾기
>fmod <link> <any option> <any option>
ex) fmod https://cafe24.com/ 0 0

12.ipaddr
>ipaddr <link> <any option> <any option>
ex) ipaddr https://ex.cafe24.com 0 0
>>>혹시 크롬에 ip찾는 확장프로그램 없을까봐 만듬

성능 업그레이드 버전은 나중에 시간되면 만들 예정

내가 가장 공을 들인건 "fuzz"와 "sqli"와 "webscn1&2"가 아닌가 싶다...

<<<제작자>>>
이지스
의뢰(discord) : 이지스#8389

(디코 자주 안봄ㅎㅎ)