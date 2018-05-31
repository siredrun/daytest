#!/usr/bin/env python
#-*- conding:utf-8 -*-
# import socket
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(('127.0.0.1', 9999))
# print(s.recv(1024).decode('utf-8'))
# for data in [b'Michael', b'Tracy', b'Sarah']:
#     s.send(data)
#     print(s.recv(1024).decode('utf-8'))
# s.send(b'exit')
# s.close()
# import socket
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# for data in [b'Michael', b'Tracy', b'Sarah']:
#     s.sendto(data, ('127.0.0.1', 9999))
#     print(s.recv(1024).decode('utf-8'))
# s.close()
# aa = 12
# bb = 'sire'
# cc = b'97'
# print('  ' * aa, bb, cc)
# from flask import Flask, request, render_template
# app = Flask(__name__)
#
# @app.route('/', methods=['GET', 'POST'])
# def home():
#     return render_template('home.html')
#
# @app.route('/signin', methods=['GET'])
# def signin_form():
#     return render_template('form.html')
#
# @app.route('/signin', methods=['POST'])
# def signin():
#     username = request.form['username']
#     password = request.form['password']
#     if username == 'admin' and password == 'password':
#         return render_template('signin-ok.html', username=username)
#     render_template('form.html', message='Bad username or password', username=username)
# if __name__ == '__main__':
#     app.run()