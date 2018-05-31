#!/usr/bin/env python
#-*- conding:utf-8 -*-
# class Student():
#     def __init__(self, name):
#         self.name = name
# def Student(name):
#     pass
# def process_student(name):
#     std = Student(name)
#     do_task_1(name)
#     do_task_2(name)
# import threading
# local_school = threading.local()
# def process_student():
#     std = local_school.student
#     print('hello, $s (in %s)' % (std, threading.current_thread().name))
# def process_thread(name):
#     local_school.student = name
#     process_student()
# aa = threading.Thread(target= process_thread, args=('sire',), name='Thread-A')
# bb = threading.Thread(target= process_thread, args=('drun',), name='Thread-B')
# aa.start()
# bb.start()
# aa.join()
# bb.join()
# import threading
# local_school = threading.local()
# def process_student():
#     std = local_school.student
#     print('Hello, %s (in %s)' % (std, threading.current_thread().name))
# def process_thread(name):
#     local_school.student = name
#     process_student()
# t1 = threading.Thread(target= process_thread, args=('Alice',), name='Thread-A')
# t2 = threading.Thread(target= process_thread, args=('Bob',), name='Thread-B')
# t1.start()
# t2.start()
# t1.join()
# t2.join()
# import random,time,queue
# from multiprocessing.managers import BaseManager
# task_queue = queue.Queue()
# result_queue = queue.Queue()
# class QueueMananger(BaseManager):
#     pass
# QueueMananger.register('get_task_queue', callable=lambda : task_queue)
# QueueMananger.register('get_result_queue', callable=lambda :result_queue)
# manager = QueueMananger(address=('', 5000), authkey=b'abc')
# manager.start()
# task = manager.get_task_queue()
# result = manager.get_result_queue()
# for i in range(10):
#     n = random.randint(0, 10000)
#     print('Put task %d' % n)
#     task.put(n)
# print('Try get results...')
# for i in range(10):
#     r = result.get(timeout=10)
#     print('Result: %s' % r)
# manager.shutdown()
# print('master exit')
# import re
# aa = re.match(r'^\d{3}\-\d{3,8}$', '010-12345')
# bb = re.match(r'^\d{3}\s\d{3,8}$', '010 12345')
# print(aa)
# print(bb)
# aa = 'a b     c'.split(' ')
# print(aa)
# # a = re.split(r'[\s\,]+', 'a, b ,    c')
# a = re.split(r'[\s\,\:]+', 'a, b ,:::    c')
# print(a)
# a = re.match('^(\d{3})-(\d{3,8}$)','010-12345')
# print(a)
# print(a.group(0))
# print(a.group(1))
# print(a.group(2))
# t = '19:05:30'
# r = re.match(r'^(0[0-9]|1[0-9]|2[0-9]|[0-9])\:(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9]|[0-9])\:(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9]|[0-9])$', t)
# print(r.groups())
# print(re.match(r'(\d+?)(0*)$', '102300').groups())
# import re
# ttn = re.compile(r'^(\d{3})-(\d{3,8})$')
# print(ttn.match('010-12345').groups())
# print(ttn.match('010-8086').groups())
# import datetime
# from datetime import datetime
# print(datetime.datetime.now())
# dt = datetime(2017,8,15,14,3,20)
# print(dt)
# print(dt.timestamp())
# aa = 1502777000.0
# print(datetime.fromtimestamp(aa))
# print(datetime.utcfromtimestamp(aa))
# print(datetime.now().strftime('%a %b %d %H %M'))
# a = datetime.now()
# print(a)
# print(a + timedelta(hours=10))
# print(a - timedelta(days=1))
# print(a + timedelta(days=2, hours=12))
# from datetime import datetime, timedelta, timezone
# a = timezone(timedelta(hours=8))
# now = datetime.now()
# print(now)
# print(now.replace(tzinfo=a))
# print(datetime.utcnow().replace(tzinfo=timezone.utc))
# aa = datetime.utcnow().replace(tzinfo=timezone.utc)
# cc = aa.astimezone(timezone(timedelta(hours=8)))
# print(cc)
# ca = cc.astimezone(timezone(timedelta(hours=9)))
# print(ca)
# cb = ca.astimezone(timezone(timedelta(hours=9)))
# print(cb)
# from collections import namedtuple
# P = namedtuple('P', ['x', 'y'])
# Circle = namedtuple('Circle', ['x', 'y', 'z'])
# p = P(1,2)
# print(p.x)
# print(p.y)
# from collections import deque
# aa = deque(['a', 'b', 'c'])
# aa.append('x')
# aa.insert(9,'y')
# aa.appendleft('z')
# print(aa)
# from collections import defaultdict
# # dd = defaultdict(lambda :['N/A'])
# # dd['a'] = 'sire'
# # print(dd['a'])
# # print(dd['b'])
# from collections import OrderedDict
# a = dict([('a', 1), ('b', 2), ('c', 3)])
# print(a)
# b = OrderedDict([('a', 1), ('b', 2), ('c', 3)])
# print(b)
# od = OrderedDict()
# od['x'] = 1
# od['y'] = 2
# od['z'] = 3
# print(od.keys())
# from collections import OrderedDict
# class aa(OrderedDict):
#     def __init__(self, capacity):
#         super(aa, self).__init__()
#         self._capacity = capacity
#     def __setitem__(self, key, value):
#         containsKey = 1 if key in self else 0
#         if len(self) - containsKey >= self._capacity:
#             last = self.popitem(last=False)
#             print('remove:', last)
#         if containsKey:
#             del self[key]
#             print('set:', (key, value))
#         else:
#             print('add:', (key, value))
#         OrderedDict.__setitem__(self, key, value)
# from collections import Counter
# c = Counter()
# for i in 'programming':
#     c[i] = c[i] +1
# print(c)
# import base64
# print(base64.b64encode(b'i\xb7\x1d\xfb\xef\xff'))
# print(base64.b64decode(b'YmluYXJ5AHN0cmluZw=='))
# print(base64.urlsafe_b64encode(b'i\xb7\x1d\xfb\xef\xff'))
# import struct
# print(struct.pack('>I', 10240099))
# print(struct.unpack('>IH', b'\xf0\xf0\xf0\xf0\x80\x80'))
# s = b'\x42\x4d\x38\x8c\x0a\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x80\x02\x00\x00\x68\x01\x00\x00\x01\x00\x18\x00'
# print(struct.unpack('<ccIIIIIIHH', s))
# md5 = hashlib.md5()
# import hashlib
# md5 = hashlib.sha1()
# md5.update('how to use md5 in python hashlib?'.encode('utf-8'))
# print(md5.hexdigest())
# import hmac
# message = b'Hello, world!'
# key = b'secret'
# p = hmac.new(key,message, digestmod='MD5')
# print(p.hexdigest())
# for n in natuals:
#     print(n)
import itertools
# natuals = itertools.count(1)
# ns = itertools.takewhile(lambda x:x <= 10, natuals)
# print(list(ns))
# for c in itertools.chain('XYZ', 'Ab3'):
#     print(c)
# for x,y in itertools.groupby('AAAGDGVDAsdsgdgredfdgfd', lambda c:c.upper()):
#     print(x, list(y))
# class Query(object):
#     def __init__(self, name):
#         self.name = name
#     def __enter__(self):
#         print('Begin')
#         return self
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         if exc_type:
#             print('error')
#         else:
#             print('end')
#     def query(self):
#         print('Query info about %s...' % self.name)
# with Query('Sire') as q:
#     # print(q)
#     q.query()
# from contextlib import contextmanager
# #
# # class Query(object):
# #
# #     def __init__(self, name):
# #         self.name = name
# #
# #     def query(self):
# #         print('Query info about %s...' % self.name)
# #
# # @contextmanager
# # def create_query(name):
# #     print('Begin')
# #     q = Query(name)
# #     yield q
# #     print('End')
# # with Query('Sire') as q:
# #     # print(q)
# #     q.query()
# from contextlib import contextmanager
# @contextmanager
# def tag(name):
#     print("<%s>" % name)
#     yield
#     print("</%s>" % name)
#
# with tag("h1"):
#     print("hello")
#     print("world")
# @contextmanager
# def tag(name):
#     print('<%s>' % name)
#     yield
#     print('<%s>' % name)
# with tag('h1'):
#     print('hi')
#     print('sire')
# from contextlib import closing
# from urllib.request import urlopen
# from contextlib import contextmanager
# with closing(urlopen('https://www.python.org')) as page:
#     for line in page:
#         print(line)
# @contextmanager
# def closing(thing):
#     try:
#         yield thing
#     finally:
#         thing.close()
# from urllib import request
# with request.urlopen('https://api.douban.com/v2/book/2129650') as f:
#     data = f.read()
#     print('Status:', f.status, f.reason)
#     for k,v in f.getheaders():
#         print('%s: %s' % (k,v))
#     print('Data:', data.decode('utf-8'))
# from urllib import request, parse
# email = input('email:')
# password = input('password:')
# login_data = parse.urlencode([
#     ('username', email),
#     ('password', password),
#     ('entry', 'mweibo'),
#     ('client_id', ''),
#     ('savestate', '1'),
#     ('ec', ''),
#     ('pagerefer', 'https://passport.weibo.cn/signin/welcome?entry=mweibo&r=http%3A%2F%2Fm.weibo.cn%2F')
# ])
# req = request.Request('https://passport.weibo.cn/sso/login')
# req.add_header('Origin', 'https://passport.weibo.cn')
# req.add_header('User-Agent',
#                'Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) '
#                'AppleWebKit/536.26 (KHTML, like Gecko) '
#                'Version/8.0 Mobile/10A5376e Safari/8536.25')
# req.add_header('Referer', 'https://passport.weibo.cn/signin/login?entry=mweibo&res=wel&wm=3349&r=http%3A%2F%2Fm.weibo.cn%2F')
# with request.urlopen(req, data=login_data.encode('utf-8')) as f:
#     print('status:', f.status, f.reason)
#     for k, v in f.getheaders():
#         print('%s: %s' % (k, v))
#     print('Data:', f.read().decode('utf-8'))
# from urllib import request,parse
# # proxy_handler =
# proxy_handler = urllib.request.ProxyHandler({'http': 'http://www.example.com:3128/'})
# proxy_auth_handler = urllib.request.ProxyBasicAuthHandler()
# proxy_auth_handler.add_password('realm', 'host', 'username', 'password')
# opener = urllib.request.build_opener(proxy_handler, proxy_auth_handler)
# with opener.open('http://www.example.com/login.html') as f:
#     pass
# from xml.parsers.expat import ParserCreate
# class DefaultSaxHandler(object):
#     def start_element(self, name, attrs):
#         print('sax: start_element:%S, attrs:%s' % (name, str(attrs)))
#     def end_element(self, name):
#         print('sax: end_element:%S' % (name))
#     def char_data(self, text):
#         print('sax:char_data: %s' % text)
# xml = r'''
# <?xml version="1.0"?>
# <ol>
#     <li><a href="/python">Python</a></li>
#     <li><a href="/ruby">Ruby</a></li>
# </ol>
# '''
# handler = DefaultSaxHandler()
# parser = ParserCreate()
# parser.StartElementHandler = handler.start_element
# parser.EndElementHandler = handler.end_element
# parser.CharDataHanlder = handler.char_data
# parser.Parse(xml)
# L = []
# L.append(r'<?xml version="1.0"?>')
# L.append(r'<root>')
# L.append(encode('some & data'))
# L.append(r'</root>')
# return ''.join(L)
# from html.parser import HTMLParser
# from html.entities import name2codepoint
# class MyHTMLParser(HTMLParser):
#     def handle_starttag(self, tag, attrs):
#         print('<%s>' % tag)
#     def handle_endtag(self, tag):
#         print('</%s>' % tag)
#     def handle_startendtag(self, tag, attrs):
#         print('<%s/>' % tag)
#     def handle_data(self, data):
#         print(data)
#
#         def handle_comment(self, data):
#             print('<!--', data, '-->')
#
#         def handle_entityref(self, name):
#             print('&%s;' % name)
#
#         def handle_charref(self, name):
#             print('&#%s;' % name)
#
#     parser = MyHTMLParser()
#     parser.feed('''<html>
#     <head></head>
#     <body>
#     <!-- test html parser -->
#         <p>Some <a href=\"#\">html</a> HTML&nbsp;tutorial...<br>END</p>
#     </body></html>''')
# import time
# print(time.localtime())
# from PIL import Image
# im = Image.open('test.jpg')
# w, h = im.size()
# print('Original image size: %sx%s' % (w, h))
# im.thumbnail((w//2, h//2))
# print('Resize image to: %sx%s' % (w//2, h//2))
# im.filter(ImageFilter.BLUR)
# im.save('thumbnail.jpg', 'jpeg')
# from PIL import Image, ImageDraw, ImageFont, ImageFilter
# import random
# #随机字母
# def rndChar():
#     return chr(random.randint(65, 90))
# #随机颜色1
# def rndColor():
#     return (random.randint(64, 255), random.randint(64, 255), random.randint(64, 255))
# #随机颜色2
# def rndColor2():
#     return (random.randint(32, 127), random.randint(32, 127), random.randint(32, 127))
# #240 * 60
# width = 60 *4
# height = 60
# image = Image.new('RGB', (width, height), (255, 255, 255))
# #font对象
# font = ImageFont.truetype('/Library/Fonts/Arial.ttf', 36)
# #draw对象
# draw = ImageDraw.Draw(image)
# # 填充每个像素
# for x in range(width):
#     for y in range(height):
#         draw.point((x, y), fill=rndColor())
# # 输出文字
# for t in range(4):
#     draw.text((60 * t + 10, 10), rndChar(), font=font, fill=rndColor2())
# image = image.Filter(ImageFilter.BLUR)
# image.save('code.jpg', 'jpeg')
# import requests
# r = requests.get('https://www.douban.com/')
# # print(r.status_code)
# # print(r.text)
# r = requests.get('https://www.douban.com/search', params={'q': 'python', 'cat': '1001'})
# print(r.url)
# print(r.encoding)
# print(r.content)
# r = requests.get('https://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20weather.forecast%20where%20woeid%20%3D%202151330&format=json')
# print(r.json())
# r = requests.get('https://www.douban.com/', headers={'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit'})
# print(r.text)
# url = 'https://www.douban.com/'
# params = {'key':'value'}
# r = requests.get(url, json=params)
# uf = {'file' : open('report.xls', 'rb')}
# r = requests.post(url, files=uf)
# print(r.headers)
# import chardet
# print(chardet.detect(b'Hello, world!'))
# print(chardet.detect('离离原上草，一岁一枯荣'.encode('gbk')))
# print(chardet.detect('最新の主要ニュース'.encode('euc-jp')))
# import psutil
# print(psutil.cpu_count())
# print(psutil.cpu_count(logical=False))
# print(psutil.cpu_times())
# for x in range(10):
#     print(psutil.cpu_percent(interval=1, percpu=True))
# print(psutil.virtual_memory())
# print(psutil.swap_memory())
# print(psutil.disk_partitions())
# print(psutil.disk_usage('/'))
# print(psutil.disk_io_counters())
# print(psutil.net_io_counters())
# print(psutil.net_if_addrs())
# print(psutil.net_if_stats())
# print(psutil.net_connections())
# print(psutil.pids())
# p = psutil.Process(1708)
# print(psutil.Process(1192))
# print(p.name())
# print(p.exe())
# print(p.cwd())
# print(p.cmdline())
# print(p.ppid())
# print(p.parent())
# print(p.children())
# print(p.status())
# print(p.username())
# print(p.create_time())
# print(p.terminal())
# print(p.cpu_times())
# print(p.memory_info())
# print(p.memory_info)
# print(p.open_files())
# print(p.num_threads())
# print(p.connections())
# print(p.threads())
# print(p.environ())
# print(p.terminate())
# print(p.terminate)
# from tkinter import *
# class Application(Frame):
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.pack()
#         self.createWidgets()
#     def createWidgets(self):
#         self.HelloLabel = Label(self, text= 'Hello, world!')
#         self.HelloLabel.pack()
#         self.quitButton = Button(self, text='Quit', command=self.quit)
#         self.quitButton.pack()
# app = Application()
# app.master.title('Hello World')
# app.mainloop()
# from tkinter import *
# import tkinter.messagebox as messagebox
# class Application(Frame):
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.pack()
#         self.createWidgets()
#     def createWidgets(self):
#         self.nameInput = Entry(self)
#         self.nameInput.pack()
#         self.alertButton = Button(self, text='Hello', command=self.hello)
#         self.alertButton.pack()
#     def hello(self):
#         name = self.nameInput.get() or 'world'
#         messagebox.showinfo('Message', 'Hello, %s' % name)
# app = Application()
# app.master.title('Hello World')
# app.mainloop()
# import socket
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(('www.sina.com.cn', 80))
# s.send(b'GET / HTTP/1.1\r\nHost: www.sina.com.cn\r\nConnection: close\r\n\r\n')
# buffer = []
# while True:
#     f = s.recv(1024)
#     if f:
#         buffer.append(f)
#     else:
#         break
# data = b''.join(buffer)
# print(data)
# s.close()
# header, html = data.split(b'\r\n\r\n', 1)
# print(header.encode('utf8'))
# with open('sina.html', 'wb') as f:
#     f.write(html)
# import socket, threading,time
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.bind(('127.0.0.1', 9999))
# s.listen(5)
# print('Waiting for connection...')
# while True:
#     sock, addr = s.accept()
#     t = threading.Thread(target=tcplink, args=(sock, addr))
#     t.start()
# def tcplink(sock, link):
#     print('Accept new connection from %s:%s...' % addr)
#     sock.send(b'Welcome!')
#     while True:
#         data = sock.recv(1024)
#         time.sleep(1)
#         if not data or data.decode('utf-8') == 'exit':
#             break
#         sock.send(('Hello, %s!' % data.decode('utf-8')).encode('utf-8'))
#     sock.close()
#     print('Connection from %s:%s closed.' % addr)
# import socket
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.bind(('127.0.0.1', 9999))
# print('Bind UDP on 9999...')
# while True:
#     data, addr = s.recvfrom(1024)
#     print('Received from %s:%s.' % addr)
#     s.sendto(b'Hello, %s!' % (data, addr))
# from email.mime.text import MIMEText
# msg = MIMEText('hello, send by Python...', 'plain', 'utf-8')
# from_addr = input('From: ')
# password = input('password: ')
# to_addr = input("to: ")
# smtp_server = input('smtp server: ')
# import smtplib
# server = smtplib.SMTP(smtp_server, 25)
# server.set_debuglevel(1)
# server.login(from_addr, password)
# server.sendmail(from_addr, [to_addr], msg.as_string())
# server.quit()
# from email import encoders
# from email.header import Header
# from email.mime.text import MIMEText
# from email.utils import parseaddr, formataddr
# import smtplib
# def _format_addr(s):
#     name, addr = parseaddr(s)
#     return formataddr((Header(name, 'utf8').encode(), addr))
# from_addr = input('From: ')
# password = input('Password: ')
# to_addr = input('To: ')
# smtp_server = input('SMTP server: ')
# msg = MIMEText('hello, send by Python...', 'plain', 'utf-8')
# msg['From'] = _format_addr('Python爱好者<%S>' % from_addr)
# msg['To'] = _format_addr('管理员<%s>' % to_addr)
# msg['Subject'] = Header('来自SMTP的问候……', 'utf-8').encode()
# server = smtplib.SMTP(smtp_server, 25)
# server.set_debuglevel(1)
# server.login(from_addr, password)
# server.sendmail(from_addr, [to_addr], msg.as_string())
# server.quit()
# import poplib
# from email.parser import Parser
# from email.header import decode_header
# from email.utils import parseaddr
# email = input('Email: ')
# password = input('Password: ')
# pop3_server = input('POP3 server: ')
# server = poplib.POP3(pop3_server)
# server.set_debuglevel(1)
# print(server.getwelcome().decode('utf8'))
# server.user(email)
# server.pass_(password)
# print('Messages: %s. Size: %s' % server.stat())
# resp, mails, octets = server.list()
# print(mails)
# index = len(mails)
# resp, lines, octets = server.retr(index)
# msg_content = b'\r\n'.join(lines).decode('utf8')
# msg = Parser().parserstr(msg_content)
# server.quit()
import poplib
from email.parser import Parser
from email.header import decode_header
# from email.utils import parseaddr
# def print_info(msg, indent=0):
#     if indent == 0:
#         for header in ['From', 'To', 'Subject']:
#             value = msg.get(header, '')
#             if value:
#                 if header == 'Subject':
#                     value = decode_str(value)
#                 else:
#                     hdr, addr = parseaddr(value)
#                     name = decode_str(hdr)
#                     value = u'%s <%s>' % (name, addr)
#             print('%s%s: %s' % ('  ' * indent, header, value))
#     if(msg.mutilpart()):
#         parts = msg.get_payload()
#         for n, part in enumerate(parts):
# import sqlite3
# conn = sqlite3.connect('test.db')
# cursor = conn.cursor()
# cursor.execute('create table user (id varchar(20) primary key, name varchar(20))')
# print(cursor.rowcount)
# cursor.execute('select * from user where id=?', ('1',))
# cursor.execute('select * from user where name=? and pwd=?', ('abc', 'password'))
# print(cursor.fetchall())
# cursor.close()
# conn.commit()
# conn.close()
# import mysql.connector
# conn = mysql.connector.connect(user='root', password='1234', database='test')
# cursor = conn.cursor()
# cursor.execute('create table user (id varchar(20) primary key, name varchar(20))')
# cursor.execute('insert into user (id, name) values (%s, %s)', ['1', 'Michael'])
# cursor.execute('select * from user where id = %s', ('1',))
# print(cursor.fetchall())
# print(cursor.rowcount)
# conn.commit()
# # cursor.close()
# class User(object):
#     def __init__(self, id, name):
#         self.id = id
#         self.name = name
# [
#     User('1', 'Micheal'),
#     User('2', 'Bob'),
#     User('3', 'Adam')
# ]
# from sqlalchemy import Column, String, create_engine
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base
# Base = declarative_base()
# class User(Base):
#     #表名
#     __tablename__ = 'user'
#     #表结构
#     id = Column(String(20), primary_key=True)
#     name = Column(String(20))
#     #一对多
#     books = relationship('Book')
# class Book(Base):
#     #表名
#     __tablename__ = 'book'
#     #表结构
#     id = Column(String(20), primary_key=True)
#     name = Column(String(20))
#     # “多”的一方的book表是通过外键关联到user表的:
#     user_id = Column(String(20), ForeignKey('user.id'))
# #初始化连接
# engine = create_engine('mysql+mysqlconnector://root:1234@localhost:3306/test')
# #DBSession
# DBSession = sessionmaker(bind=engine)
# #session对象
# session = DBSession()
#user用户
# new_user = User(id='5', name='Bob')
# #添加到session
# session.add(new_user)
# session.commit()
# user = session.query(User).filter(User.id == '5').one()
# print('type:%s' % type(user))
# print('name:', user.name)
# session.close()
# def application(environ, start_response):
#     start_response('200 OK', [('Content-Type', 'text/html')])
#     return [b'<h1>Hello, web!</h1>']
# from wsgiref.simple_server import make_server
# httpd = make_server('', 8000, application)
# print('Serving HTTP on port 8000...')
# httpd.serve_forever()
# from flask import Flask
# from flask import request
# app = Flask(__name__)
# @app.route('/', methods=['GET', 'POST'])
# def home():
#     return '<h1>Home</h1>'
# @app.route('/signin', methods=['GET'])
# def signin_form():
#     return '''<form action="/signin" method="post">
#               <p><input name="username"></p>
#               <p><input name="password" type="password"></p>
#               <p><button type="submit">Sign In</button></p>
#               </form>'''
# @app.route('/signin', methods=['POST'])
# def signin():
#     # 需要从request对象读取表单内容：
#     if request.form['username'] == 'admin' and request.form['password'] == 'password':
#         return '<h3>Hello, admin!</h3>'
#     return '<h3>Bad username or password.</h3>'
# if __name__ == '__main__':
#     app.run()
# from flask import Flask, request, render_template
# def consumer():
#     r = ''
#     while True:
#         n = yield r
#         if not n:
#             return
#         print('[CONSUMER] Consuming %s...' % n)
#         r = '200 ok'
# def produce(c):
#     c.send(None)
#     n = 0
#     while n < 5:
#         n = n + 1
#         print('[PRODUCER] Producing %s...' % n)
#         r = c.send(n)
#         print('[PRODUCER] Consumer return: %s' % r)
#     c.close()
# c = consumer()
# produce(c)
# import threading
# import asyncio
# @asyncio.coroutine
# def hello():
#     print('hello world(%s)' % threading.currentThread())
#     r = yield from asyncio.sleep(1)
#     print('Hello again!(%s)' % threading.currentThread())
# loop = asyncio.get_event_loop()
# tasks = [hello(), hello()]
# loop.run_until_complete(asyncio.wait(tasks))
# loop.close()
# import async
# @async.coroutine
# def wget(host):
#     print('wget %s...' % host)
#     conn = async.open_connection(host, 80)
#     reader, writer = yield from conn
#     header = 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % host
#     writer.write(header.encode('utf8'))
#     yield from writer.drain()
#     while True:
#         line = yield from reader.readline()
#         if line == b'\r\n':
#             break
#         print('%s header > %s' % (host, line.decode('utf8').rstrip()))
#     writer.close()
# loop = asyncio.get_event_loop()
# tasks = [wget(host) for host in ['www.sina.com.cn', 'www.sohu.com', 'www.163.com']]
# loop.run_until_complete(asyncio.wait(tasks))
# loop.close()
# import asyncio
# from aiohttp import web
# async def index(request):
#     await asyncio.wait(0.5)
#     return web.Response(body=b'<h1>Index</h1>')
# async def hello(request):
#     await asyncio.wait(0.5)
#     text = '<h1>hello, %s!</h1>' % request.match_info('name')
#     return web.Response(body=text.encode('utf8'))
# async def init(loop):
#     app = web.Application(loop=loop)
#     app.router.add_route('GET', '/', index)
#     app.router.add_route('GET', '/hello/{name}', hello)
#     srv = await loop.create_server(app.make_handler(), '127.0.0.1', 8000)
#     print('Server started at http://127.0.0.1:8000...')
#     return srv
# loop = asyncio.get_event_loop()
# loop.run_until_complete(init(loop))
# loop.run_forever()
# import os
# print(os.path.abspath('.'))
# print(__file__)
# import sys
#
# print(sys.argv)
# import sys
#
# print(sys.executable)





