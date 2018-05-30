#!/usr/bin/env python
# -*- coding:utf-8 -*-
import json
import os
import struct
import socket
import sys
import hashlib

PATH = (os.path.dirname(os.path.dirname(__file__)))


class Ftp:
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    allow_reuse_address = False
    max_packet_size = 8192
    coding = 'utf-8'
    request_queue_size = 5
    server_dir = 'file_upload'
    home_dir = 'home'
    user_info_name = 'user.json'
    server_file_path = os.path.normpath(os.path.join(PATH, server_dir))
    home_file_path = os.path.normpath(os.path.join(PATH, home_dir))
    user_info_path = os.path.normpath(os.path.join(PATH, 'db/%s' % (user_info_name)))
    user_f = open(user_info_path, 'r', encoding=coding)
    user_info_db = json.load(user_f)

    def __init__(self, server_address, bind_and_activate=True):
        self.server_address = server_address
        self.socket = socket.socket(self.address_family,
                                    self.socket_type)
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise

    def server_bind(self):
        '''
        绑定IP和端口
        :return:
        '''
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    def server_activate(self):
        '''
        绑定最大链接数
        :return:
        '''
        self.socket.listen(self.request_queue_size)

    def server_close(self):
        '''
        关闭服务
        '''
        self.socket.close()

    def get_request(self):
        '''建立链接'''
        return self.socket.accept()

    def close_request(self, request):
        '''关闭链接'''
        return request.close()



    def run(self):#运行程序
        while True:
            print('starting....')
            self.conn, self.client_addr = self.get_request()  # 打开链接
            print('clinet：', self.client_addr)
            while True:
                # try:
                    login_head_struct = self.conn.recv(4)  # 接收报文头的长度
                    if not login_head_struct: break  # 判断是否为空
                    login_head_len = struct.unpack('i', login_head_struct)[0]  # 获取登陆信息报文头长度信息
                    login_head_json = self.conn.recv(login_head_len)  # 接收真正数据 .dencode(self.coding)
                    self.login_head_dic = json.loads(login_head_json)
                    user = self.login_head_dic['user']
                    password = self.login_head_dic['password']
                    if self.user_info_db.get(user, False) and self.user_info_db[user]['password'] == password:
                        print('验证成功')
                        self.conn.send(b'0')
                        self.user_home_dir = os.path.normpath(os.path.join(self.home_file_path, self.login_head_dic['user'])) #获取用户家目录
                        self.work_dir = os.chdir(self.user_home_dir)#切换工作目录
                        self.user_home_file = (os.listdir(os.getcwd()))#获取用户下文件
                        while True:
                            head_struct = self.conn.recv(4)  # 接收报文头的长度
                            head_len = struct.unpack('i', head_struct)[0]  # 获取登陆信息报文头长度信息
                            head_json = self.conn.recv(head_len)  # 接收真正数据
                            head_dic = json.loads(head_json)
                            cmd = head_dic['cmd']
                            if hasattr(self, cmd):
                                func = getattr(self, cmd)  # 根据命令执行特定的函数
                                func(head_dic)
                                continue

                    else:
                        self.conn.send(b'1')
                        print('验证失败')
                        continue




    def ls(self,args):
        file_db = {'file':[],'folder':[]}
        for f in self.user_home_file:
            if os.path.isdir(f):
                file_db['folder'].append(f)
            else:
                file_db['file'].append(f)
        user_head_json = json.dumps(file_db)
        user_head_bytes = bytes(user_head_json, encoding=self.coding)
        user_struct = struct.pack('i', len(user_head_bytes))
        self.conn.send(user_struct)
        self.conn.send(user_head_bytes)
        print('查看成功')
        return 0

    def cd(self,args): #切换目录
        file_db = {'file': [], 'folder': []}
        for f in self.user_home_file:
            if os.path.isdir(f):
                file_db['folder'].append(f)
            else:
                file_db['file'].append(f)
        user_head_json = json.dumps(file_db)
        user_head_bytes = bytes(user_head_json, encoding=self.coding)
        user_struct = struct.pack('i', len(user_head_bytes))
        self.conn.send(user_struct)
        self.conn.send(user_head_bytes)
        res = self.conn.recv(1).decode(self.coding)
        if res == '0':
            #接收文件名
            while True:

                cd_head_struct = self.conn.recv(4)  # 接收报文头的长度
                if not cd_head_struct: break  # 判断是否为空
                cd_head_len = struct.unpack('i', cd_head_struct)[0]  #
                cd_head_json = self.conn.recv(cd_head_len)  # 接收真正数据 .dencode(self.coding)
                cd_head_dic = json.loads(cd_head_json)
                dir_name = cd_head_dic['dir_name']
                target_dir = os.path.normpath(os.path.join(os.getcwd(),dir_name))
                self.work_dir = os.chdir(target_dir) #刷新当前路径
                self.user_home_file = (os.listdir(os.getcwd()))
                return

        else:
            return

    def go(self,args):
            go_path = (os.path.abspath(os.path.dirname(os.getcwd())))
            home_dir = (os.path.split(os.path.dirname(os.getcwd())))
            if home_dir[1] == 'home':
                print('切换失败')
                self.conn.send(b'1')
                return
            else:
                self.work_dir = os.chdir(go_path)
                self.user_home_file = (os.listdir(os.getcwd()))
                print('切换成功')
                self.conn.send(b'0')
                return





    def put(self, args):
        '''上传程序'''
        file_path = os.path.normpath(os.path.join(os.getcwd(),args['file_name']))
        recv_size = 0
        file_size = int(args['file_size'])
        file_md5 = args['file_md5']
        with open(file_path, 'wb') as f:
            while recv_size < file_size:
                recv_data = self.conn.recv(self.max_packet_size)
                f.write(recv_data)
                recv_size += len(recv_data)
                print('recvsize:%s filesize:%s' % (recv_size, file_size))
            else:
                f.close()
                myhash = hashlib.md5()
                f = open(file_path, 'rb')
                while True:
                    b = f.read(8096)
                    if not b:
                        break
                    myhash.update(b)
                f.close()
                fmd5 = (myhash.hexdigest())
                if fmd5 == file_md5:
                    print('upload  success')
                    print('{}:文件正常'.format(args['file_name']), fmd5, file_md5)
                    self.conn.send(b'0')
                    return
                else:
                    print('upload  success')
                    self.conn.send(b'1')
                    print('{}:文件不正常'.format(args['file_name']), fmd5, file_md5)
                    return

    def get(self,args):
        get_db = args
        filename = get_db['file_name']
        file_path = os.path.normpath(os.path.join(os.getcwd(), filename))
        if os.path.isfile(file_path):
            self.conn.send(b'0')
            work_path = os.getcwd()
            self.file_size = os.path.getsize(file_path)

            myhash = hashlib.md5() #md5
            f = open(file_path, 'rb')
            while True:
                b = f.read(8096)
                if not b:
                    break
                myhash.update(b)
            f.close()
            fmd5 = (myhash.hexdigest())
            get_dic = {'file_name': '{}'.format(args['file_name']),
                       'file_size': '{}'.format(self.file_size), 'file_md5': '{}'.format(fmd5)}
            get_head_json = json.dumps(get_dic)
            get_head_bytes = bytes(get_head_json, encoding=self.coding)
            get_struct = struct.pack('i', len(get_head_bytes))
            self.conn.send(get_struct)
            self.conn.send(get_head_bytes)
            with open(file_path, 'rb') as  file:
                recv_size = 0
                for values in file:
                    bytes_values = bytes(values)
                    self.conn.send(bytes_values)
                else:
                    file.close()
                    print('download  success ')
                    return

        else:
            print('文件不存在')
            self.conn.send(b'1')
            return



if __name__ == '__main__':
    ftp = Ftp(('127.0.0.1', 999))
    ftp.run()

    # print(os.path.normpath(os.path.join(PATH,'db/user.json')))
