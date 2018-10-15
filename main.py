#-*- coding: utf8 -*-
'''
版权声明
    1. 热土(上海)网络科技有限公司(andadata.com) 对本程序(光纤接入设备AI故障诊断程序及服务、业务/后台服务、客户端/网页应用系统) 享有版权。
    2. 对于上述版权内容，超越合理使用范畴、并未经本公司书面许可的使用行为，我公司均保留追究法律责任的权利。
Copyright ©2018-2019 ReTu(Shanghai). All Rights Reserved. 热土(上海)网络科技有限公司 版权所有
'''
from flask import Flask, redirect, url_for, request, render_template, make_response, jsonify, send_from_directory, flash,session,g
from flask_login import (LoginManager, current_user, login_required,user_accessed,
                            login_user, logout_user, UserMixin,AnonymousUserMixin,
                            confirm_login, fresh_login_required)

from flask_paginate import Pagination
import flask_paginate
# 配合本系统的css
flask_paginate.CSS_LINKS = dict(bootstrap='<div><ul class="pagination pagination-lg">',
                 bootstrap2='<div><ul class="pagination pagination-lg">',
                 bootstrap3='<ul class="pagination pagination-lg">',
                 foundation='<ul class="pagination pagination-lg">',
                 )

from werkzeug.utils import secure_filename
import sys
import os
import threading
import time
import datetime
import random
import hashlib
import requests
import json
import decimal
from flask_apscheduler import APScheduler
import uuid
import qrcode
import urllib

from time import sleep

from onu_tools import *
from const import *
import config
import dbtools
from sqltmpl import *

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_, func,and_

app = Flask(__name__)

app.config.update(
    SECRET_KEY='123456'
)


# database setting
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + config.database_config["user"] + ':' + config.database_config["password"] + '@' + config.database_config["host"] + ':' + str(config.database_config["port"]) + '/' + config.database_config["databasename"] + '?charset=' + config.database_config["charset"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_POOL_SIZE'] = 50

scheduler = APScheduler()
scheduler.init_app(app=app)
scheduler.start()

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# DB相关
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
db = SQLAlchemy(app)


# user table
class User(db.Model):
    __tablename__ = 'o_user'

    id = db.Column(db.INT)
    broadbandid = db.Column(db.String(40), primary_key=True)
    username = db.Column(db.String(40))
    password = db.Column(db.String(40))
    name = db.Column(db.String(40))
    telephone = db.Column(db.String(40))
    town = db.Column(db.String(40))
    address = db.Column(db.String(80))
    expiretime = db.Column(db.String(40))
    engineerid = db.Column(db.String(40))
    registertime = db.Column(db.String(40))
    islogin = db.Column(db.String(40))
    qrcodeid = db.Column(db.String(40))
    onu_type = db.Column(db.String(40))
    onu_model = db.Column(db.String(40))
    lon = db.Column(db.Float)
    lat = db.Column(db.Float)
    wx_openid = db.Column(db.String(40))
    status = db.Column(db.String(20))
    is_registered = db.Column(db.String(20))
    area = db.Column(db.String(20))


# task table
class Task(db.Model):
    __tablename__ = 'o_task'

    id = db.Column(db.INT)
    taskid = db.Column(db.String(40), primary_key=True)
    pictureid = db.Column(db.String(40))
    status = db.Column(db.String(40))
    createtime = db.Column(db.String(40))
    starttime = db.Column(db.String(40))
    finishtime = db.Column(db.String(40))
    ucomment = db.Column(db.String(80))
    ecomment = db.Column(db.String(80))
    warn = db.Column(db.String(40))
    updatetime = db.Column(db.String(40))
    engineer_id = db.Column(db.String(40))
    overtime = db.Column(db.String(40))


# engineer table
class Engineer(db.Model):
    __tablename__ = 'o_engineer'

    id = db.Column(db.INT)
    employeeid = db.Column(db.String(40), primary_key=True)
    e_password = db.Column(db.String(40))
    e_name = db.Column(db.String(40))
    e_telephone = db.Column(db.String(40))
    e_groupid = db.Column(db.String(40))
    lastviewtime = db.Column(db.String(40))
    wx_openid = db.Column(db.String(40))
    incharge_area = db.Column(db.String(300))
    status = db.Column(db.String(20))


# picture table
class Picture(db.Model):
    __tablename__ = 'o_picture'

    pictureid = db.Column(db.String(40), primary_key=True)
    broadbandid = db.Column(db.String(40))
    uploadtime = db.Column(db.String(40))
    resulttime = db.Column(db.String(40))
    model = db.Column(db.String(40))
    lightsinfo = db.Column(db.String(240))
    instruction = db.Column(db.String(1200))
    feedback = db.Column(db.String(40))


'''
# office table
if False:
    class Office(db.Model):
        __tablename__ = 'o_office'

        o_id = db.Column(db.Integer, primary_key=True)
        o_name = db.Column(db.String(40))


# suboffice table
if False:
    class Suboffice(db.Model):
        __tablename__ = 'o_suboffice'

        s_id = db.Column(db.Integer, primary_key=True)
        s_name = db.Column(db.String(40))
        officeid = db.Column(db.Integer)
'''

# group table
class Group(db.Model):
    __tablename__ = 'o_group'

    g_id = db.Column(db.Integer, primary_key=True)
    g_name = db.Column(db.String(40))
    subofficeid = db.Column(db.String(40))


# imported user table
class Imported_user(db.Model):
    __tablename__ = 'imported_user'

    broadbandid = db.Column(db.String(40), primary_key=True)
    name = db.Column(db.String(40))
    telephone = db.Column(db.String(40))
    town = db.Column(db.String(40))
    address = db.Column(db.String(80))
    expiretime = db.Column(db.String(40))
    engineerid = db.Column(db.String(40))


class Sys_province(db.Model):
    '''省级列表'''
    __tablename__ = 'o_sys_province'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))


class Sys_city(db.Model):
    '''市级列表'''
    __tablename__ = 'o_sys_city'

    id = db.Column(db.Integer, primary_key=True)
    province_id = db.Column(db.Integer)
    name = db.Column(db.String(50))


class Sys_county(db.Model):
    '''县级列表'''
    __tablename__ = 'o_sys_county'

    id = db.Column(db.Integer, primary_key=True)
    city_id = db.Column(db.Integer)
    name = db.Column(db.String(50))


class Sys_area(db.Model):
    '''街道乡镇列表'''
    __tablename__ = 'o_sys_area'

    id = db.Column(db.Integer, primary_key=True)
    county_id = db.Column(db.Integer)
    name = db.Column(db.String(50))


class Sys_block(db.Model):
    '''小区列表'''
    __tablename__ = 'o_sys_block'

    id = db.Column(db.Integer, primary_key=True)
    area_id = db.Column(db.Integer)
    name = db.Column(db.String(50))


def tolist(mylists):
    result = []
    for mylist in mylists:
        tmp = mylist.__dict__
        tmp.pop('_sa_instance_state', None)
        result.append(tmp)
    return result


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# 以下使用flask-login进行权限验证
class FlaskUser(UserMixin):
    def __init__(self, name, id, role, active=True):
        self.name = name
        self.id = id
        self.role = role
        self.active = active

    @property
    def is_active(self):
        return self.active


class Anonymous(AnonymousUserMixin):
    name = u"Anonymous"

login_manager = LoginManager()

login_manager.anonymous_user = Anonymous
login_manager.login_view = "backend_login"
login_manager.login_message = u"请登录。"
login_manager.refresh_view = "reauth"
# 配置REMEMBER_COOKIE_DOMAIN
# app.config['REMEMBER_COOKIE_DOMAIN'] = ".ANDADATA.com"
login_manager.init_app(app)

def redirect_back(endpoint, **values):
    target = request.form['next']
    if not target:
        target = url_for(endpoint, **values)
    return redirect(target)


@app.before_request
def before_request():
    g.user = current_user


@login_manager.user_loader
def load_user(id):
    '''参考 https://segmentfault.com/q/1010000010253582 '''
    user = None
    try:
        if str(id).split(',')[0] == "manager":
            sql = "select id,name,status from o_manager where status is null and id=%s limit 1" % (int(str(id).split(',')[1]))
            row = dbtools.query_one(db, sql)
            if len(row) > 0:
                user = FlaskUser(row[1], row[0], "manager", True)

                user.privilege = OUserPrivilege(user.id, db)
        elif str(id).split(',')[0] == "user":
            sql = "select id,name,status from o_user where status is null and id=%s limit 1" % (int(str(id).split(',')[1]))
            row = dbtools.query_one(db, sql)
            if len(row) > 0:
                user = FlaskUser(row[1], row[0], "user", True)
        elif str(id).split(',')[0] == "engineer":
            sql = "select id,e_name,status from o_engineer where status is null and id=%s limit 1" % (int(str(id).split(',')[1]))
            row = dbtools.query_one(db, sql)
            if len(row) > 0:
                user = FlaskUser(row[1], row[0], "engineer", True)
    except Exception, e:
        print e

    return user

@user_accessed.connect_via(app)
def when_user_accessed(sender, **extra):
    user_id = session.get('user_id')
    # 下面可以开始自己的操作流程了, 需要对 user_id 进行判断
    # 首次发送时, user_id 可能为空
    if user_id:
        # db.session.execute("update o_user set login_date=now() where id=%s"%user_id)
        pass


def login_ok(username, user_id , role, remember=False):
    '''登录成功后的后续状态处理 (user_id等记录进入session)'''
    user = FlaskUser(username, user_id, role, True)
    if login_user(user, remember=remember):
        return True

    return False


@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("reauth.html")


@app.route("/logout")
@login_required
def logout():
    role = str(session.get('user_id')).split(',')[0]
    logout_user()
    flash("Logged out.")
    print role
    if role == 'manager' or not check_mobile(request):
        return redirect(url_for("backend_login"))
    else:
        return redirect(url_for("login"))

# 以上使用Flask-login进行权限验证
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

@app.errorhandler(404)
@app.errorhandler(500)
def page_not_found(err):
    return redirect(url_for("backend_404"))


# index
@app.route('/', methods=["GET", "POST"])
def app_index():
    ''' 主页 '''

    try:
        code = request.args.get('code')
        posturl = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + APPID + \
                  "&secret=" + APPSECRET + \
                  "&code=" + code + \
                  "&grant_type=authorization_code"

        ret = requests.get(posturl)
        result = json.loads(ret.text)
        openid = result['openid']
        return render_template("login.html", OPENID=openid)
    except Exception, e:
        print e

    return render_template("login.html")




# page error
@app.route('/page_error')
def page_error():
    '''
        错误页面
    '''
    return render_template('page_error.html')





USER_ANDADATA = 'ANDADATA'


def check_login(username, password, openid, method, nlng, nlat):
    ''' 登录检查 '''
    if method == '0':  # broadband login
        if db.session.query(User).filter(User.broadbandid == username).filter(User.status == None).all():
            if password == '123456':
                utmp = db.session.query(User).filter(User.broadbandid == username).filter(User.status == None).all()
                udetial = tolist(utmp)
                etmp = db.session.query(Engineer).filter(User.broadbandid == username).filter(Engineer.employeeid == User.engineerid).filter(Engineer.status == None).limit(1).all()
                edetial = tolist(etmp)
                login_ok(username, "user,"+str(udetial[0]['id']), "user")

                wxopenid = db.session.query(User.wx_openid).filter(User.broadbandid == username).filter(User.status == None)[0][0]

                if wxopenid == '' or wxopenid is None:
                    sql = 'update o_user set wx_openid = "{}" where broadbandid="{}"'.format(openid, username)
                    dbtools.update(db, sql)
                    dbtools.commit(db)

                lon = db.session.query(User.lon).filter(User.broadbandid == username).filter(User.status == None)[0][0]
                lat = db.session.query(User.lat).filter(User.broadbandid == username).filter(User.status == None)[0][0]

                if lon == '' or lon is None or lat == '' or lat is None:
                    sql = 'update o_user set lon = "{}",lat = "{}" where broadbandid="{}"'.format(nlng, nlat, username)
                    dbtools.update(db, sql)
                    dbtools.commit(db)

                return jsonify({'status': '1', 'errmsg': '用户登录成功', 'udetial': udetial, 'edetial': edetial})
            return jsonify({'status': '-1', 'errmsg': '手机号验证码错误！'})
        return jsonify({'status': '-1', 'errmsg': '该宽带账号不存在！'})

    elif method == '1':  # username&password login
        if db.session.query(Engineer).filter(Engineer.employeeid == username).filter(Engineer.status == None).all():
            if password == '123456':

                etmp = db.session.query(Engineer).filter(Engineer.employeeid == username).filter(Engineer.status == None).all()
                edetial = tolist(etmp)
                login_ok(username, "engineer,"+str(edetial[0]['id']), "engineer")

                wxopenid = db.session.query(Engineer.wx_openid).filter(Engineer.employeeid == username).filter(Engineer.status == None)[0][0]

                if wxopenid == '' or wxopenid is None:
                    sql = 'update o_engineer set wx_openid = "{}" where employeeid="{}"'.format(openid, username)
                    dbtools.update(db, sql)
                    dbtools.commit(db)

                return jsonify({'status': '2', 'errmsg': '装维登录成功', 'edetial': edetial})
            return jsonify({'status': '-1', 'errmsg': '密码错误！'})

        return jsonify({'status': '-1', 'errmsg': '该装维工号不存在！'})

    elif method == '2':  # qrcode login
        sql = 'select count(qrcodeid) from o_user where qrcodeid = "{}" and status is null'.format(username)
        sqlret = dbtools.query_one(db, sql)[0]

        if sqlret >= 1:
            if password == 'ANDADATA':
                utmp = db.session.query(User).filter(User.qrcodeid == username).filter(User.status == None)
                udetial = tolist(utmp)
                etmp = db.session.query(Engineer).filter(User.qrcodeid == username).filter(Engineer.employeeid == User.engineerid).filter(Engineer.status == None)
                edetial = tolist(etmp)
                login_ok(username, "user,"+str(udetial[0]['id']),"user")

                wxopenid = db.session.query(User.wx_openid).filter(User.qrcodeid == username).filter(User.status == None)[0][0]

                if wxopenid == '' or wxopenid is None :
                    sql = 'update o_user set wx_openid = "{}" where qrcodeid="{}"'.format(openid, username)
                    dbtools.update(db, sql)
                    dbtools.commit(db)

                lon = db.session.query(User.lon).filter(User.qrcodeid == username).filter(User.status == None)[0][0]
                lat = db.session.query(User.lat).filter(User.qrcodeid == username).filter(User.status == None)[0][0]

                if lon == '' or lon is None or lat == '' or lat is None:
                    sql = 'update o_user set lon = "{}",lat = "{}" where qrcodeid="{}"'.format(nlng, nlat, username)
                    dbtools.update(db, sql)
                    dbtools.commit(db)

                return jsonify({'status': '1', 'errmsg': '用户登录成功', 'udetial': udetial, 'edetial': edetial})
            return jsonify({'status': '-1', 'errmsg': '二维码不存在！'})
        return jsonify({'status': '-1', 'errmsg': '二维码不存在！'})

    else:
        return jsonify({'status': '-1', 'errmsg': '未知错误！'})


@app.route('/get_detial_msg', methods=["GET", "POST"])
def get_detial_msg():
    if request.method == 'POST':
        login_mothod = request.form['method']
        username = request.form['username']
        password = request.form['password']

        if login_mothod == '0':
            utmp = db.session.query(User).filter(User.broadbandid == username).filter(User.status == None).all()
            udetial = tolist(utmp)
            etmp = db.session.query(Engineer).filter(User.broadbandid == username).filter(
                Engineer.employeeid == User.engineerid).filter(Engineer.status == None).limit(1).all()
            edetial = tolist(etmp)
            return jsonify({'status': 'success', 'errmsg': '用户验证成功！', 'udetial': udetial, 'edetial': edetial})
        elif login_mothod == '1':
            etmp = db.session.query(Engineer).filter(Engineer.employeeid == username).filter(
                Engineer.status == None).all()
            edetial = tolist(etmp)
            return jsonify({'status': 'success', 'errmsg': '装维验证成功！', 'edetial': edetial})
        elif login_mothod == '2':
            utmp = db.session.query(User).filter(User.qrcodeid == username).filter(User.status == None)
            udetial = tolist(utmp)
            etmp = db.session.query(Engineer).filter(User.qrcodeid == username).filter(
                Engineer.employeeid == User.engineerid).filter(Engineer.status == None)
            edetial = tolist(etmp)
            return jsonify({'status': 'success', 'errmsg': '用户验证成功！', 'udetial': udetial, 'edetial': edetial})

        return jsonify({'status': 'failure', 'errmsg': '验证失败！'})

    else:
        return jsonify({'status': 'failure', 'errmsg': '未知错误！'})


@app.route('/get_verify_code', methods=["GET", "POST"])
def get_verify_code():
    if request.method == 'POST':
        username = request.form['username']
        telephone = request.form['telephone']
        role = request.form['role']
        if role == 'user':
            sql = 'select count(broadbandid) from o_user where broadbandid = "{}" and telephone = "{}"'.format(username, telephone)
            sqlret = dbtools.query_one(db, sql)[0]
            if sqlret == 1:
                return jsonify({'status': 'success', 'errmsg': '用户验证成功！'})
        elif role == 'engineer':
            sql = 'select count(employeeid) from o_engineer where employeeid = "{}" and e_telephone = "{}"'.format(username, telephone)
            sqlret = dbtools.query_one(db, sql)[0]
            if sqlret == 1:
                return jsonify({'status': 'success', 'errmsg': '装维验证成功！'})

        return jsonify({'status': 'failure', 'errmsg': '验证失败！'})

    else:
        return jsonify({'status': 'failure', 'errmsg': '未知错误！'})


# login
@app.route('/login')
def login():
    ''' 登录首页 '''
    if not check_mobile(request):
        return redirect("/backend/login")

    return render_template('login.html')


# login confirm
@app.route('/login_confirm')
@login_required
def login_confirm():
    ''' 登录验证 '''
    return render_template('login_confirm.html')


# signin confirm
@app.route('/signin_confirm')
def signin_confirm():
    ''' 激活验证 '''
    return render_template('signin_confirm.html')


@app.route("/onu_login_b", methods=["GET", "POST"])
def onu_login_b():
    '''
        宽带账号登录
    '''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        openid = request.form['openid']
        lng = request.form['lng']
        lat = request.form['lat']
        method = '0'

        return check_login(username, password, openid, method, lng, lat)
    else:
        return render_template('login.html')


@app.route("/onu_login_u", methods=["GET", "POST"])
def onu_login_u():
    '''
        账号密码登录
    '''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        openid = request.form['openid']
        lng = request.form['lng']
        lat = request.form['lat']
        method = '1'

        return check_login(username, password, openid, method, lng, lat)
    else:
        return render_template('login.html')


@app.route("/onu_login_q", methods=["GET", "POST"])
def onu_login_q():
    '''
        二维码登录
    '''
    if request.method == 'POST':
        username = request.form['qrcodeid']
        password = request.form['password']
        openid = request.form['openid']
        lng = request.form['lng']
        lat = request.form['lat']
        method = '2'

        return check_login(username, password, openid, method, lng, lat)
    else:
        return render_template('login.html')


@app.route("/onu_user_signin", methods=["GET", "POST"])
def onu_user_signin():
    '''
        用户注册
    '''
    if request.method == 'POST':
        userid = request.form['userid']

        if db.session.query(User).filter(User.id == userid).filter(User.status == None).all():
            db.session.query(User).filter(User.id == userid).filter(User.status == None).update({
                User.is_registered: "YES"
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '注册成功'})

    return jsonify({'status': 'failure', 'errmsg': '注册失败'})
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以下为用户部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

# user login
@app.route("/onu_user")
@login_required
def onu_user():
    '''
        用户登录首页
    '''
    return render_template('user_client/onu_user_info.html')


@app.route("/onu_user_uppic")
@login_required
def onu_user_uppic():
    '''
        用户上传图片
    '''
    return render_template('user_client/onu_user_takepic.html')


@app.route("/onu_user_task")
@login_required
def onu_user_task():
    '''
        用户工单列表
    '''
    return render_template('user_client/onu_user_tasks.html')


@app.route("/onu_user_task_detail")
@login_required
def onu_user_task_detail():
    '''
        用户工单详情
    '''
    return render_template('user_client/onu_user_tasks_detial.html')


@app.route("/onu_user_setting")
@login_required
def onu_user_setting():
    '''
        用户设置页面
    '''
    return render_template('user_client/onu_user_info.html')


@app.route("/onu_user_info_tel")
@login_required
def onu_user_info_tel():
    '''
        用户修改手机页面
    '''
    return render_template('user_client/onu_user_info_tel.html')


@app.route("/change_user_tel", methods=["GET", "POST"])
def change_user_tel():
    '''
        用户修改电话
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        telephone = request.form['telephone']

        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).update({
                User.telephone: telephone,
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '修改成功！'})
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})
    else:
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})


@app.route("/onu_user_update", methods=["GET", "POST"])
def onu_user_update():
    '''
        用户修改登录名和密码
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        username = request.form['username']
        password = request.form['password']

        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).update({
                User.username: username,
                User.password: password,
            })
            db.session.commit()

            return jsonify({'status': '1', 'errmsg': '修改成功！'})
        return jsonify({'status': '0', 'errmsg': '修改失败！'})
    else:
        return jsonify({'status': '0', 'errmsg': '修改失败！'})


# onu picture upload
@app.route('/onu_upload', methods=['POST', 'GET'])
def onu_upload():
    '''
        用户上传图片
    '''
    if request.method == 'POST':
        f = request.files['file']
        f.filename = str(int(round(time.time() * 1000)))+".png"
        basepath = os.path.dirname(__file__)
        upload_path = os.path.join(basepath, 'static/uploads', secure_filename(f.filename))
        f.save(upload_path)

        return jsonify({'status': '1', 'errmsg': f.filename})

    return jsonify({'status': '-1', 'errmsg': '上传失败'})


class JsonUtil:
    ''' Json
        http://www.yihaomen.com/article/python/487.htm
    '''
    def __default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        else:
            raise TypeError('%r is not JSON serializable' % obj)

    def parseJsonObj(self, obj):
        jsonstr = json.dumps(obj, default=self.__default, ensure_ascii=False)
        return jsonstr

    def parseJsonString(self,jsonstring):
        obj = json.loads(jsonstring)
        return obj


def write_airesult(pictureid, broadbandid, uploadtime, resulttime, model, lightsinfo, instruction):
    '''
        将AI识别结果存入数据库
    '''
    newPicture = Picture(pictureid=pictureid, broadbandid=broadbandid, uploadtime=uploadtime, resulttime=resulttime,
                         model=model, lightsinfo=lightsinfo, instruction=instruction, feedback='暂无')
    db.session.add(newPicture)
    db.session.commit()


@app.route('/testajax', methods=['POST', 'GET'])
def testajax():
    if request.method == 'POST':
        print request.files['file']

        lights = ["POWER", "PON", "LOS", "LAN"]

        ret = {'label': "ceshi1", 'light': lights}

        return jsonify(ret)

@app.route('/onu_ajax_predict')
def onu_ajax_predict():
    '''
        ajax请求AI进行图片识别
    '''
    nowtime = datetime.datetime.now()
    uploadtime = nowtime.strftime('%Y-%m-%d %H:%M:%S')
    pictureid = request.args.get('param')
    broadbandid = request.args.get('broadbandid')
    status_code = '[AI服务无响应]'
    try:
        upload_folder = sys.path[0] + r'/static/uploads/'
        filename = request.args.get('param')
        fullpath = upload_folder + filename

        model = ''
        lightsinfo = ''
        lightlist = []
        result = {}

        api_app = False
        if filename.lower() != '':
            files = {'file': (filename, open(fullpath, 'rb'), 'image/jpg')}
            if api_app:
                srvurl = 'http://aipromote.cn/app'
            else:
                srvurl = 'http://ai.ANDADATA.com:9099/aitest'
                # srvurl = 'http://192.168.1.6:9099/aitest'
            jsonres = requests.post(srvurl, data={}, files=files)
            if jsonres.status_code:
                status_code = ' [返回码:{}]'.format(jsonres.status_code)
            result = json.loads(jsonres.text)
            try:
                if api_app:
                    model = result['result'][0].upper()
                    model = model.split(':')[0].upper()
                else:
                    model = result['label'].upper()
                    lightlist = result['light']

                    if lightlist:
                        lightsinfo = ', '.join(lightlist).upper()

                    else:
                        lightsinfo = ''
            except Exception, e:
                print e

        instruction = ''
        if lightlist:
            instruction = "\n\n".join(result['trouble']['solution'])
        else:
            instruction = u'没有检测到指示灯状态，请首先确保电源连接正常。若问题依然存在，请呼叫您的专属服务工程师。'

        nowtime = datetime.datetime.now()
        resulttime = nowtime.strftime('%Y-%m-%d %H:%M:%S')
        result = {'info': '', 'modelinfo': model, 'lightsinfo': lightsinfo,
                  'lightlist': lightlist, 'instruction': instruction}
        lighttest = ''
        for key, value in lightlist.items():
            if key != 'type':
                lighttest += "%s,%s," % (key.upper(), value)
        lighttest = lighttest[0:-1]
        write_airesult(pictureid, broadbandid, uploadtime, resulttime, model, lighttest, instruction)
        res = JsonUtil().parseJsonObj(result)
        return res
    except Exception, e:
        print e

    nowtime = datetime.datetime.now()
    resulttime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

    result = {'info': '', 'modelinfo': '识别失败 {}'.format(status_code), 'lightsinfo': '', 'instruction': '无'}
    write_airesult(pictureid, broadbandid, uploadtime, resulttime, '识别失败 {}'.format(status_code), '', '无')
    res = JsonUtil().parseJsonObj(result)
    return res


# ai result finish
@app.route('/onu_user_survey', methods=['POST', 'GET'])
def onu_user_survey():
    '''
        用户通过AI解决问题的评价
    '''
    if request.method == 'POST':
        pictureid = request.form['pictureid']
        feedback = request.form['feedback']

        if db.session.query(Picture).filter(Picture.pictureid == pictureid).all():
            db.session.query(Picture).filter(Picture.pictureid == pictureid).update({
                Picture.feedback: feedback
            })

            db.session.commit()

            return jsonify({'status': '1', 'errmsg': '评论成功'})

        else:
            return jsonify({'status': '-1', 'errmsg': '评论失败'})
    else:
        return render_template('page_error.html')


# onu picture report
@app.route("/onu_report")
@login_required
def onu_report():
    '''
        光猫助手AI识别页面
    '''
    return render_template('user_client/onu_user_report.html')


# user survey
@app.route("/onu_survey")
@login_required
def onu_survey():
    '''
        光猫助手识别评价页面
    '''
    return render_template('user_client/onu_user_ai_survey.html')


# user send task
@app.route("/send_task", methods=['POST', 'GET'])
def send_task():
    '''
         用户提交新的故障单
    '''
    if request.method == 'POST':
        pictureid = request.form['pictureid']
        tengineerid = request.form['tengineerid']

        print tengineerid

        nowtime = datetime.datetime.now()
        createtime = nowtime.strftime('%Y-%m-%d %H:%M:%S')
        task_id = nowtime.strftime('%Y%m%d-%H%M%S-')
        for i in range(6):
            task_id += str(random.randint(0, 9))

        if not db.session.query(Task).filter(Task.taskid == task_id).all():
            newTask = Task(taskid=task_id, pictureid=pictureid, status="未处理", createtime=createtime,
                           ucomment="暂无", ecomment="暂无", warn="0",
                           updatetime=createtime, engineer_id=tengineerid)
            db.session.add(newTask)
            db.session.commit()

            if db.session.query(Engineer.wx_openid).filter(Engineer.id == tengineerid).all():
                userid = db.session.query(Engineer.wx_openid).filter(Engineer.id == tengineerid).all()[0][0]
                ttmp = db.session.query(Task.id, User.name, User.address).filter(Task.taskid == task_id).\
                    filter(Task.pictureid == Picture.pictureid).filter(Picture.broadbandid == User.broadbandid).all()
                if userid != '' and userid is not None:
                    wx_send_template_new(str(userid).strip(), "http://onu.ANDADATA.com/onu_engineer_task_edit?edit_taskid="+task_id,
                                str(ttmp[0][0]), "光猫", str(ttmp[0][2]), str(ttmp[0][1]), nowtime.strftime('%Y年%m月%d日 %H:%M:%S'))

            return jsonify({'status': '1', 'errmsg': '发送成功'})
        else:
            return jsonify({'status': '-1', 'errmsg': '发送失败'})
    else:
        return render_template('page_error.html')


# get user task
@app.route("/get_user_task", methods=['POST', 'GET'])
def get_user_task():
    '''
        获取用户的故障单列表
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']

        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            pictures = db.session.query(Picture).filter(Picture.broadbandid == broadbandid).filter(
                Picture.pictureid == Task.pictureid).all()
            tasks = db.session.query(Task).filter(Picture.broadbandid == broadbandid).filter(
                Picture.pictureid == Task.pictureid).all()

            picturelist = tolist(pictures)
            tasklist = tolist(tasks)
            return jsonify({'status': 'success', 'errmsg': '获取成功', 'picturelist': picturelist, 'tasklist': tasklist})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


# get more user task
@app.route("/get_more_user_task", methods=['POST', 'GET'])
def get_more_user_task():
    '''
        获取用户的故障单列表
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']


        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            result = db.session.query(Task, Picture).filter(Task.pictureid == Picture.pictureid).filter(Picture.broadbandid == broadbandid).\
                    order_by(desc(Task.createtime)).all()
            pictures = []
            tasks = []
            engineers = []


            service_engineer = db.session.query(Engineer).filter(Engineer.employeeid == "000000").all()[0]

            nownum = int(pageid) * int(pagenum)
            for i in range(0, len(result)):
                if i >= nownum and i < nownum + int(pagenum):
                    pictures.append(result[i][1])
                    tasks.append(result[i][0])
                    if result[i][0].engineer_id is None:
                        engineers.append(service_engineer)
                    else:
                        this_engineer = db.session.query(Engineer).filter(Engineer.id == result[i][0].engineer_id).all()
                        if this_engineer:
                            engineers.append(this_engineer[0])
                        else:
                            engineers.append(service_engineer)

            listend = "no"
            if nownum + int(pagenum) >= len(result):
                listend = "yes"

            picturelist = tolist(pictures)
            tasklist = tolist(tasks)
            engineerlist = tolist(engineers)

            detialtasklist = []

            for i in range(0, len(tasklist)):
                detialtasklist.append(
                    dic_merge(dic_merge(tasklist[i], picturelist[i]), engineerlist[i]))
            return jsonify({'status': 'success', 'errmsg': '获取成功',  'tasklist': detialtasklist, 'listend': listend})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


def user_task_warn_wx(taskid):
    '''用户微信催单提醒'''
    if db.session.query(Engineer.wx_openid).filter(Task.taskid == taskid).filter(Task.engineer_id == Engineer.id).all():
        userid = \
        db.session.query(Engineer.wx_openid).filter(Task.taskid == taskid).filter(Task.engineer_id == Engineer.id).all()[0][
            0]
        ttmp = db.session.query(Task.taskid, Task.id, User.name, User.telephone, Task.createtime).filter(
            Task.taskid == taskid). \
            filter(Task.pictureid == Picture.pictureid).filter(Picture.broadbandid == User.broadbandid).all()

        if userid != '' and userid is not None:
            wx_send_template_urge(str(userid).strip(),
                                      str("http://onu.ANDADATA.com/onu_engineer_task_edit?edit_taskid=" + ttmp[0][0]),
                                      str(ttmp[0][1]), str(ttmp[0][2]), str(ttmp[0][3]))


# user task warn
@app.route("/user_task_warn", methods=['POST', 'GET'])
def user_task_warn():
    '''
        用户催单
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']
        nowtime = datetime.datetime.now()
        updatetime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

        if db.session.query(Task).filter(Task.taskid == taskid).all():
            taskWarn = db.session.query(Task.warn).filter(Task.taskid == taskid).all()[0][0]
            taskUpdateTime = db.session.query(Task.updatetime).filter(Task.taskid == taskid).all()[0][0]
            if taskWarn == '0':
                db.session.query(Task).filter(Task.taskid == taskid).update({
                    Task.warn: '1',
                    Task.updatetime: updatetime
                })
                db.session.commit()
                user_task_warn_wx(taskid)

                return jsonify({'status': 'success', 'errmsg': '催单成功', 'updatetime': updatetime})
            elif taskWarn == '1' and taskUpdateTime + datetime.timedelta(minutes=15) > datetime.datetime.now():
                return jsonify({'status': 'wait', 'errmsg': '催单失败', 'lastupdatetime': taskUpdateTime})
            elif taskWarn == '1' and taskUpdateTime + datetime.timedelta(minutes=15) <= datetime.datetime.now():
                db.session.query(Task).filter(Task.taskid == taskid).update({
                    Task.warn: '1',
                    Task.updatetime: updatetime
                })
                db.session.commit()
                user_task_warn_wx(taskid)

                return jsonify({'status': 'success', 'errmsg': '催单成功', 'updatetime': updatetime})

    return jsonify({'status': 'failure', 'errmsg': '催单失败'})


# user task survey
@app.route("/onu_user_task_survey")
@login_required
def onu_user_task_survey():
    '''
       故障单用户评价界面
    '''
    return render_template('user_client/onu_user_task_survey.html')


# send user task survey
@app.route("/send_user_task_survey", methods=['POST', 'GET'])
def send_user_task_survey():
    '''
       发送故障单用户评价
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']
        ucomment = request.form['ucomment']

        if db.session.query(Task).filter(Task.taskid == taskid).all():
            db.session.query(Task).filter(Task.taskid == taskid).update({
                Task.ucomment: ucomment
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '评论成功'})

    return jsonify({'status': 'failure', 'errmsg': '评论失败'})

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以上为用户部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


def dic_merge(dica, dicb):
    dic = {}
    for key in dica:
        dic[key] = dica[key]
    for key in dicb:
        if dica.get(key):
            pass
        else:
            dic[key] = dicb[key]

    return dic


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以下为装维部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

# engineer login
@app.route("/onu_engineer_user")
@login_required
def onu_engineer_user():
    '''
        装维用户列表页面
    '''
    return render_template('engineer_client/onu_engineer_users.html')


@app.route("/onu_engineer_user_add")
@login_required
def onu_engineer_user_add():
    '''
        装维用户添加页面
    '''
    return render_template('engineer_client/onu_engineer_users_add.html')


@app.route("/onu_engineer_user_edit")
@login_required
def onu_engineer_user_edit():
    '''
        装维用户编辑页面
    '''
    return render_template('engineer_client/onu_engineer_users_edit.html')


# show engineer task
@app.route("/onu_engineer_task")
@login_required
def onu_engineer_task():
    '''
        装维工单列表页面
    '''
    return render_template('engineer_client/onu_engineer_tasks.html')


@app.route("/onu_engineer_task_edit")
@login_required
def onu_engineer_task_edit():
    '''
        装维工单编辑页面
    '''
    return render_template('engineer_client/onu_engineer_tasks_edit.html')


@app.route("/onu_engineer_task_survey")
@login_required
def onu_engineer_task_survey():
    '''
        装维工单评价页面
    '''
    return render_template('engineer_client/onu_engineer_tasks_survey.html')


@app.route("/onu_engineer_setting")
@login_required
def onu_engineer_setting():
    '''
        装维设置页面
    '''
    return render_template('engineer_client/onu_engineer_info.html')


@app.route("/onu_engineer_info_tel")
@login_required
def onu_engineer_info_tel():
    '''
        装维修改手机页面
    '''
    return render_template('engineer_client/onu_engineer_info_tel.html')


@app.route("/onu_engineer_info_area")
@login_required
def onu_engineer_info_area():
    '''
        装维区域管理页面
    '''
    return render_template('engineer_client/onu_engineer_info_area.html')


@app.route("/onu_engineer_info_report")
@login_required
def onu_engineer_info_report():
    '''
        装维每周报表页面
    '''
    return render_template('engineer_client/onu_engineer_info_report.html')


@app.route("/onu_engineer_tasks_news")
@login_required
def onu_engineer_tasks_news():
    '''
        装维工单消息页面
    '''
    return render_template('engineer_client/onu_engineer_tasks_news.html')


@app.route("/get_task_nums", methods=["GET", "POST"])
def get_task_nums():
    '''
        获取订单总数
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            result = db.session.query(func.count(Task.id)).filter(Task.engineer_id == Engineer.id).filter(Engineer.employeeid == employeeid).all()

            return jsonify({'status': 'success', 'errmsg': '查询成功！', 'task_nums': result[0][0]})
        return jsonify({'status': 'failure', 'errmsg': '查询失败！'})
    else:
        return jsonify({'status': 'failure', 'errmsg': '查询失败！'})


@app.route("/get_user_nums", methods=["GET", "POST"])
def get_user_nums():
    '''
        获取用户总数
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            result = db.session.query(func.count(User.id)).filter(User.engineerid == employeeid).filter(User.status == None).all()

            return jsonify({'status': 'success', 'errmsg': '查询成功！', 'user_nums': result[0][0]})
        return jsonify({'status': 'failure', 'errmsg': '查询失败！'})
    else:
        return jsonify({'status': 'failure', 'errmsg': '查询失败！'})


@app.route("/change_engineer_tel", methods=["GET", "POST"])
def change_engineer_tel():
    '''
        装维修改电话
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']
        telephone = request.form['telephone']

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            db.session.query(Engineer).filter(Engineer.employeeid == employeeid).update({
                Engineer.e_telephone: telephone,
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '修改成功！'})
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})
    else:
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})


# check broadbandid
@app.route("/check_broadbandid", methods=["GET", "POST"])
def check_boradbandid():
    '''
        检查宽带账号
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        if not db.session.query(Imported_user).filter(Imported_user.broadbandid == broadbandid).all():
            if not db.session.query(User).filter(User.broadbandid == broadbandid).all():
                return jsonify({'status': 'success', 'errmsg': '该宽带账号可使用！'})
            else:
                return jsonify({'status': 'failure', 'errmsg': '该宽带账号已注册！'})
        else:
            if not db.session.query(User).filter(User.broadbandid == broadbandid).all():
                imported_user = db.session.query(Imported_user).filter(Imported_user.broadbandid == broadbandid).all()

                user_message = tolist(imported_user)

                return jsonify({'status': 'success_have', 'errmsg': '该宽带账号可使用！', 'umessage': user_message})
            else:
                return jsonify({'status': 'failure', 'errmsg': '该宽带账号已注册！'})

    return jsonify({'status': 'failure', 'errmsg': '错误请求！'})


@app.route("/search_more_tasks", methods=['POST', 'GET'])
def search_more_tasks():
    '''
        获取更多工单列表
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']
        searchmsg = request.form['searchmsg']
        option = request.form['option']

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            result = None
            if option == "全部":
                result = db.session.query(Task, Picture, User, Group).filter(Engineer.employeeid == employeeid).\
                    filter(User.town == Group.g_id).filter(Task.pictureid == Picture.pictureid).\
                    filter(Picture.broadbandid == User.broadbandid).\
                    filter(Task.engineer_id == Engineer.id).filter(User.status == None).\
                    filter(or_(User.name.like('%'+searchmsg+'%'), User.telephone.like('%'+searchmsg+'%'),
                               Task.id.like('%'+searchmsg+'%'), Group.g_name.like('%'+searchmsg+'%'))).order_by(desc(Task.createtime)).all()
            elif option == "未处理" or option == "处理中" or option == "已处理":
                result = db.session.query(Task, Picture, User, Group).filter(Engineer.employeeid == employeeid). \
                    filter(User.town == Group.g_id).filter(Task.pictureid == Picture.pictureid). \
                    filter(Picture.broadbandid == User.broadbandid). \
                    filter(Task.engineer_id == Engineer.id).filter(User.status == None).\
                    filter(Task.status == option). \
                    filter(or_(User.name.like('%' + searchmsg + '%'), User.telephone.like('%' + searchmsg + '%'),
                               Task.id.like('%' + searchmsg + '%'),
                               Group.g_name.like('%' + searchmsg + '%'))).order_by(desc(Task.createtime)).all()
            elif option == "告警":
                result = db.session.query(Task, Picture, User, Group).filter(Engineer.employeeid == employeeid). \
                    filter(User.town == Group.g_id).filter(Task.pictureid == Picture.pictureid). \
                    filter(Picture.broadbandid == User.broadbandid). \
                    filter(Task.engineer_id == Engineer.id).filter(User.status == None).\
                    filter(Task.overtime != None). \
                    filter(or_(User.name.like('%' + searchmsg + '%'), User.telephone.like('%' + searchmsg + '%'),
                               Task.id.like('%' + searchmsg + '%'),
                               Group.g_name.like('%' + searchmsg + '%'))).order_by(desc(Task.createtime)).all()
            else:
                return jsonify({'status': 'failure', 'errmsg': '获取失败'})

            tasks = []
            pictures = []
            users = []
            groups = []
            nownum = int(pageid) * int(pagenum)
            for i in range(0, len(result)):
                if i >= nownum and i < nownum + int(pagenum):
                    tasks.append(result[i][0])
                    pictures.append(result[i][1])
                    users.append(result[i][2])
                    groups.append(result[i][3])

            listend = "no"
            if nownum + int(pagenum) >= len(result):
                listend = "yes"

            tasklist = tolist(tasks)
            picturelist = tolist(pictures)
            userlist = tolist(users)
            grouplist = tolist(groups)

            detialtasklist = []

            for i in range(0, len(tasklist)):
                detialtasklist.append(dic_merge(dic_merge(dic_merge(tasklist[i], picturelist[i]), userlist[i]), grouplist[i]))

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'tasklist': detialtasklist, 'listend': listend})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/user_latest_task", methods=['POST', 'GET'])
def user_latest_task():
    '''
        寻找用户最新工单
    '''
    if request.method == 'POST':
        qrcode = request.form['qrcode']
        engineerid = request.form['engineerid']

        if db.session.query(User).filter(User.qrcodeid == qrcode).filter(User.status == None):
            user_taskid = db.session.query(Task.taskid, Task.id, User.name).filter(Task.pictureid == Picture.pictureid).\
                filter(Task.status == '未处理').filter(Task.engineer_id == engineerid).\
                filter(Picture.broadbandid == User.broadbandid).\
                filter(User.qrcodeid == qrcode).filter(User.status == None).order_by(desc(Task.createtime)).all()
            if user_taskid:
                ret_taskid = user_taskid[0][0]
                ret_id = user_taskid[0][1]
                ret_name = user_taskid[0][2]
                return jsonify({'status': 'success', 'errmsg': "寻找到工单", 'ret_taskid': ret_taskid, 'ret_id': ret_id, 'ret_name': ret_name})
            else:
                return jsonify({'status': 'failure', 'errmsg': "未寻找到工单"})

        return jsonify({'status': 'failure', 'errmsg': '二维码不存在'})

    return jsonify({'status': 'failure', 'errmsg': '请求失败'})


@app.route("/transfer_task", methods=['POST', 'GET'])
def transfer_task():
    '''
        工单改派
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']

        if db.session.query(Task).filter(Task.taskid == taskid):
            db.session.query(Task).filter(Task.taskid == taskid).update({
                Task.engineer_id: None
            })

            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': "工单已改派"})
        return jsonify({'status': 'failure', 'errmsg': '工单不存在'})

    return jsonify({'status': 'failure', 'errmsg': '请求失败'})


def engineer_task_change_wx(taskid, status):
    '''用户微信催单提醒'''
    if db.session.query(User.wx_openid).filter(Task.taskid == taskid).filter(Task.pictureid == Picture.pictureid).\
            filter(Picture.broadbandid == User.broadbandid).all():
        userid = db.session.query(User.wx_openid).filter(Task.taskid == taskid).filter(Task.pictureid == Picture.pictureid).\
            filter(Picture.broadbandid == User.broadbandid).all()[0][0]
        ttmp = db.session.query(Task.taskid, Task.id, Engineer.e_name).filter(
            Task.taskid == taskid). \
            filter(Task.engineer_id == Engineer.id).all()

        if userid != '' and userid is not None:
            if status == "处理中":
                 wx_send_template_status(str(userid).strip(),
                                  str("http://onu.ANDADATA.com/onu_user_task_detail?taskid=" + ttmp[0][0]),
                                  str(ttmp[0][1]), "光猫故障", status, str(ttmp[0][2]), "请点击查看详情")
            elif status == "已处理":
                 wx_send_template_status(str(userid).strip(),
                                        str("http://onu.ANDADATA.com/onu_user_task_detail?taskid=" + ttmp[0][0]),
                                        str(ttmp[0][1]), "光猫故障", status, str(ttmp[0][2]), "请点击完成评价")


# start_task
@app.route("/start_task", methods=['POST', 'GET'])
def start_task():
    '''
        开始工单
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']

        nowtime = datetime.datetime.now()
        starttime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

        if db.session.query(Task).filter(Task.taskid == taskid):
            db.session.query(Task).filter(Task.taskid == taskid).update({
                Task.starttime: starttime,
                Task.status: "处理中",
                Task.warn: "0",
                Task.overtime: None
            })

            db.session.commit()
            engineer_task_change_wx(taskid, "处理中")
            return jsonify({'status': 'success', 'errmsg': "工单处理中", 'starttime': starttime})
        return jsonify({'status': 'failure', 'errmsg': '工单不存在'})

    return jsonify({'status': 'failure', 'errmsg': '请求失败'})


# finish task
@app.route("/finish_task", methods=['POST', 'GET'])
def finish_task():
    '''
        结束工单
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']

        nowtime = datetime.datetime.now()
        finishtime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

        if db.session.query(Task).filter(Task.taskid == taskid):
            db.session.query(Task).filter(Task.taskid == taskid).update({
                Task.finishtime: finishtime,
                Task.status: "已处理",
                Task.warn: "0",
                Task.overtime: None
            })

            db.session.commit()
            engineer_task_change_wx(taskid, "已处理")
            return jsonify({'status': 'success', 'errmsg': "工单已处理", 'finishtime': finishtime})
        return jsonify({'status': 'failure', 'errmsg': '工单不存在'})

    return jsonify({'status': 'failure', 'errmsg': '请求失败'})


# send engineer task survey
@app.route("/send_engineer_task_survey", methods=['POST', 'GET'])
def send_engineer_task_survey():
    '''
       发送故障单装维评价
    '''
    if request.method == 'POST':
        taskid = request.form['taskid']
        ecomment = request.form['ecomment']

        if db.session.query(Task).filter(Task.taskid == taskid).all():
            db.session.query(Task).filter(Task.taskid == taskid).update({
                Task.ecomment: ecomment
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '评论成功'})

    return jsonify({'status': 'failure', 'errmsg': '评论失败'})


@app.route("/update_lastviewtime", methods=['POST', 'GET'])
def update_lastviewtime():
    '''
       记录装维查看消息时间
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']

        nowtime = datetime.datetime.now()
        lastviewtime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            db.session.query(Engineer).filter(Engineer.employeeid == employeeid).update({
                Engineer.lastviewtime: lastviewtime
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '更新成功', 'lastviewtime': lastviewtime})

    return jsonify({'status': 'failure', 'errmsg': '更新失败'})


@app.route("/search_more_users", methods=['POST', 'GET'])
def search_more_users():
    '''
        获取更多用户列表
    '''
    if request.method == 'POST':
        employeeid = request.form['employeeid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']
        searchmsg = request.form['searchmsg']

        if db.session.query(Engineer).filter(Engineer.employeeid == employeeid).filter(Engineer.status == None).all():
            result = db.session.query(User).filter(User.engineerid == employeeid).filter(User.status == None).\
                filter(or_(User.name.like('%'+searchmsg+'%'), User.telephone.like('%'+searchmsg+'%'), User.address.like('%'+searchmsg+'%'))).order_by(desc(User.registertime)).all()

            new_result = []

            nownum = int(pageid) * int(pagenum)

            for i in range(0, int(pagenum)):
                if nownum + i < len(result):
                    new_result.append(result[nownum + i])

            listend = "no"
            if nownum + int(pagenum) >= len(result):
                listend = "yes"

            userlist = tolist(new_result)

            for userl in userlist:
                userl['town'] = db.session.query(Group.g_name).filter(Group.g_id == userl['town']).all()[0][0]
            return jsonify({'status': 'success', 'errmsg': '获取成功', 'userlist': userlist, 'listend': listend})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


# add new user
@app.route("/onu_add_user", methods=["GET", "POST"])
def onu_add_user():
    '''
        添加用户
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        name = request.form['name']
        telephone = request.form['telephone']
        address = request.form['address']

        onutype = request.form['onutype']
        onumodel = request.form['onumodel']

        qrcodeid = request.form['qrcodeid']

        engineerid = request.form['engineerid']
        town = request.form['town']

        area = request.form['area']

        nowtime = datetime.datetime.now()
        registertime = nowtime.strftime('%Y-%m-%d %H:%M:%S')

        if not db.session.query(User).filter(User.broadbandid == broadbandid).all():
            if not db.session.query(User).filter(User.telephone == telephone).all():
                if not db.session.query(User).filter(User.qrcodeid == qrcodeid).all():
                    newUser = User(broadbandid=broadbandid, username=telephone, password=telephone, name=name,
                                   telephone=telephone, town=town, address=address, registertime=registertime,
                                   engineerid=engineerid, islogin="0",
                                   qrcodeid=qrcodeid, onu_type=onutype, onu_model=onumodel, is_registered="NO", area=area)
                    db.session.add(newUser)
                    db.session.commit()

                    new_utmp = db.session.query(User).filter(User.broadbandid == broadbandid).all()
                    new_ulist = tolist(new_utmp)

                    return jsonify({'status': 'success', 'errmsg': '添加成功', 'new_user': new_ulist})
                return jsonify({'status': 'failure', 'errmsg': '该二维码无法被多次绑定，请重试'})
            return jsonify({'status': 'failure', 'errmsg': '该手机号码已注册，请更换重试'})
        return jsonify({'status': 'failure', 'errmsg': '该宽带账号已存在，请更换重试'})

    return jsonify({'status': 'failure', 'errmsg': '添加失败'})


# edit user
@app.route("/onu_edit_user", methods=["GET", "POST"])
def onu_edit_user():
    '''
        修改用户
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']
        name = request.form['name']
        telephone = request.form['telephone']
        address = request.form['address']

        onutype = request.form['onutype']
        onumodel = request.form['onumodel']

        qrcodeid = request.form['qrcodeid']
        area = request.form['area']

        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).update({
                User.name: name,
                User.telephone: telephone,
                User.address: address,
                User.onu_type: onutype,
                User.onu_model: onumodel,
                User.qrcodeid: qrcodeid,
                User.area: area,
            })

            db.session.commit()

            new_utmp = db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all()
            new_ulist = tolist(new_utmp)

            return jsonify({'status': 'success', 'errmsg': '修改成功', 'new_user': new_ulist})

    return jsonify({'status': 'failure', 'errmsg': '修改失败'})


# delete user
@app.route("/onu_delete_user", methods=["GET", "POST"])
def onu_delete_user():
    '''
        删除用户
    '''
    if request.method == 'POST':
        broadbandid = request.form['broadbandid']

        if db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).all():
            db.session.query(User).filter(User.broadbandid == broadbandid).filter(User.status == None).update({
                User.status: "DELETED"
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '删除成功'})

    return jsonify({'status': 'failure', 'errmsg': '删除失败'})


@app.route("/get_province", methods=["GET", "POST"])
def get_porvince():
    '''
        获取省份信息
    '''
    if request.method == 'POST':

        result = db.session.query(Sys_province).all()

        retlist = tolist(result)

        return jsonify({'status': 'success', 'errmsg': '获取成功', 'retlist': retlist })

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/get_city", methods=["GET", "POST"])
def get_city():
    '''
        获取城市信息
    '''
    if request.method == 'POST':
        provinceid = request.form['provinceid']

        if db.session.query(Sys_province).filter(Sys_province.id == provinceid):
            result = db.session.query(Sys_city).filter(Sys_city.province_id == provinceid).all()

            retlist = tolist(result)

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'retlist': retlist })

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/get_county", methods=["GET", "POST"])
def get_county():
    '''
        获取区县信息
    '''
    if request.method == 'POST':
        cityid = request.form['cityid']

        if db.session.query(Sys_city).filter(Sys_city.id == cityid):
            result = db.session.query(Sys_county).filter(Sys_county.city_id == cityid).all()

            retlist = tolist(result)

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'retlist': retlist })

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/get_town", methods=["GET", "POST"])
def get_town():
    '''
        获取乡镇信息
    '''
    if request.method == 'POST':
        countyid = request.form['countyid']

        if db.session.query(Sys_county).filter(Sys_county == countyid):
            result = db.session.query(Sys_area).filter(Sys_area.county_id == countyid).all()

            retlist = tolist(result)

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'retlist': retlist })

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})

@app.route("/onu_engineer_exist_block", methods=["GET", "POST"])
def onu_engineer_exist_block():
    '''
        获取已有小区信息
    '''
    if request.method == 'POST':

        engineerid = request.form['engineerid']

        eresult = db.session.query(Engineer).filter(Engineer.id == engineerid).filter(Engineer.status == None).all()
        elist = tolist(eresult)

        if elist[0]['incharge_area'] is not None:

            arealist = []

            if len(elist) > 0:
                arealist = str(elist[0]['incharge_area']).split(',')

            for i in range(0, len(arealist)):
                arealist[i] = int(arealist[i])

            result = db.session.query(Sys_block).filter(Sys_block.id.in_(arealist)).all()

            existlist = tolist(result)

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'existlist': existlist})
        return jsonify({'status': 'success', 'errmsg': '获取成功', 'existlist': []})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/onu_engineer_get_block", methods=["GET", "POST"])
def onu_engineer_get_block():
    '''
        获取小区信息
    '''
    if request.method == 'POST':

        engineerid = request.form['engineerid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']
        searchmsg = request.form['searchmsg']

        eresult = db.session.query(Engineer).filter(Engineer.id == engineerid).filter(Engineer.status == None).all()
        elist = tolist(eresult)

        arealist = []

        if len(elist) > 0 and elist[0]['incharge_area'] is not None:
            arealist = str(elist[0]['incharge_area']).split(',')

        for i in range(0, len(arealist)):
            arealist[i] = int(arealist[i])

        result = db.session.query(Sys_block).filter(Sys_block.name.like('%' + searchmsg + '%')).filter(Sys_block.id.notin_(arealist)).all()

        new_result = []

        nownum = int(pageid) * int(pagenum)

        for i in range(0, int(pagenum)):
            if nownum + i < len(result):
                new_result.append(result[nownum + i])


        listend = "no"
        if nownum + int(pagenum) >= len(result):
            listend = "yes"

        blocklist = tolist(new_result)

        return jsonify({'status': 'success', 'errmsg': '获取成功', 'blocklist': blocklist, 'listend': listend})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/onu_engineer_search_block", methods=["GET", "POST"])
def onu_engineer_search_block():
    '''
        获取小区信息
    '''
    if request.method == 'POST':

        engineerid = request.form['engineerid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']
        searchmsg = request.form['searchmsg']

        result = db.session.query(Sys_block).filter(Sys_block.name.like('%' + searchmsg + '%')).all()

        new_result = []

        nownum = int(pageid) * int(pagenum)

        for i in range(0, int(pagenum)):
            if nownum + i < len(result):
                new_result.append(result[nownum + i])

        listend = "no"
        if nownum + int(pagenum) >= len(result):
            listend = "yes"

        blocklist = tolist(new_result)

        return jsonify({'status': 'success', 'errmsg': '获取成功', 'blocklist': blocklist, 'listend': listend})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/onu_engineer_save_block", methods=["GET", "POST"])
def onu_engineer_save_block():
    '''
        装维修改小区
    '''
    if request.method == 'POST':
        engineerid = request.form['engineerid']
        blockmsg = request.form['blockmsg']

        if blockmsg == '':
            blockmsg = None

        if db.session.query(Engineer).filter(Engineer.id == engineerid).filter(Engineer.status == None).all():
            db.session.query(Engineer).filter(Engineer.id == engineerid).update({
                Engineer.incharge_area: blockmsg,
            })
            db.session.commit()

            return jsonify({'status': 'success', 'errmsg': '修改成功！'})
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})
    else:
        return jsonify({'status': 'failure', 'errmsg': '修改失败！'})


def get_score_average(dbret):
    '''
        获取评价字符串前四位分数的平均值
    '''
    total = 0
    num = 0
    for tmp in dbret:
        total += int(str(tmp[0])[0])+int(str(tmp[0])[1])+int(str(tmp[0])[2])+int(str(tmp[0])[3])
        num += 4

    if num == 0:
        return 0
    else:
        return round(total*1.0/num, 1)


def get_week_report(engineerid, employeeid, weekstart, weekend):
    '''获取报告信息'''
    ret = {}

    # 新增工单数
    sql = 'select count(*) from o_task where engineer_id = "{}" and "{}" < createtime and createtime < "{}"'.format(
        engineerid, weekstart, weekend)
    sqlret = dbtools.query_one(db, sql)[0]
    ret['new_task_cnt'] = sqlret

    # 完成工单数
    sql = 'select count(*) from o_task where engineer_id = "{}" and "{}" < finishtime and finishtime < "{}"'.format(
        engineerid, weekstart, weekend)
    sqlret = dbtools.query_one(db, sql)[0]
    ret['done_task_cnt'] = sqlret

    # 平均工单完成时间
    sql = 'select AVG(UNIX_TIMESTAMP(finishtime)-UNIX_TIMESTAMP(starttime)) from o_task where engineer_id = "{}" and "{}" < finishtime and finishtime < "{}"'.format(
        engineerid, weekstart, weekend)
    sqlret = dbtools.query_one(db, sql)[0]
    if sqlret:
        ret['avg_task_time'] = round(sqlret/3600, 1)
    else:
        ret['avg_task_time'] = 0

    result = db.session.query(Task.ucomment).filter(Task.ucomment != '暂无').\
        filter(Task.engineer_id == engineerid).filter(Task.finishtime < weekend).filter(Task.finishtime > weekstart).all()
    ret['avg_task_score'] = get_score_average(result)

    # 新增用户数
    sql = 'select count(*) from o_user where engineerid = "{}" and "{}" < registertime and registertime < "{}" and status is null '.format(employeeid, weekstart, weekend)
    sqlret = dbtools.query_one(db, sql)[0]
    ret['new_user_cnt'] = sqlret

    # 机器处理故障数
    sql = 'SELECT COUNT(*) FROM o_picture,o_user where o_picture.broadbandid = o_user.broadbandid and o_user.engineerid = "{}" and o_picture.feedback <> "暂无" and "{}" < o_picture.uploadtime and o_picture.uploadtime < "{}"'.format(
        employeeid, weekstart, weekend)
    sqlret = dbtools.query_one(db, sql)[0]
    ret['ai_success_cnt'] = sqlret

    return ret


@app.route("/onu_engineer_report", methods=["GET", "POST"])
def onu_engineer_report():
    '''
        获取报告信息
    '''
    if request.method == 'POST':
        engineer_id = request.form['engineerid']
        employee_id = request.form['employeeid']

        this_week_start = request.form['thisWeekStart']
        this_week_end = request.form['thisWeekEnd']
        last_week_start = request.form['lastWeekStart']
        last_week_end = request.form['lastWeekEnd']

        this_week_ret = get_week_report(engineer_id, employee_id, this_week_start, this_week_end)
        last_week_ret = get_week_report(engineer_id, employee_id, last_week_start, last_week_end)

        compare_rate = {}

        for key in this_week_ret.keys():
            if last_week_ret[key] == 0:
                if this_week_ret[key] == 0:
                    compare_rate[key] = 0
                else:
                    compare_rate[key] = 100
            else:
                rate = 100 * (this_week_ret[key] - last_week_ret[key]) / last_week_ret[key]
                compare_rate[key] = int(rate)

        res = render_template('/engineer_client/part_report_content.html', this_week_ret=this_week_ret, last_week_ret=last_week_ret, compare_rate=compare_rate)
        return res
        #return jsonify({'status': 'success', 'errmsg': '获取成功', 'thisWeekRet': this_week_ret, 'lastWeekRet': last_week_ret })

    #return jsonify({'status': 'failure', 'errmsg': '获取失败'})
    return 'ERR'


@app.route("/onu_engineer_get_news", methods=["GET", "POST"])
def onu_engineer_get_news():
    '''
        获取工单消息
    '''
    if request.method == 'POST':

        engineerid = request.form['engineerid']
        pageid = request.form['pageid']
        pagenum = request.form['pagenum']

        if db.session.query(Engineer).filter(Engineer.id == engineerid).filter(Engineer.status == None).all():
            result = db.session.query(Task, Picture, User, Group).filter(Task.engineer_id == Engineer.id).\
                filter(Engineer.id == engineerid).filter(Picture.pictureid == Task.pictureid).\
                filter(Picture.broadbandid == User.broadbandid).filter(User.town == Group.g_id).\
                filter(or_(Task.status == '未处理', Task.warn == '1')).order_by(desc(Task.updatetime)).all()

            tasks = []
            pictures = []
            users = []
            groups = []
            nownum = int(pageid) * int(pagenum)
            for i in range(0, len(result)):
                if i >= nownum and i < nownum + int(pagenum):
                    tasks.append(result[i][0])
                    pictures.append(result[i][1])
                    users.append(result[i][2])
                    groups.append(result[i][3])

            listend = "no"
            if nownum + int(pagenum) >= len(result):
                listend = "yes"

            tasklist = tolist(tasks)
            picturelist = tolist(pictures)
            userlist = tolist(users)
            grouplist = tolist(groups)

            detialtasklist = []

            for i in range(0, len(tasklist)):
                detialtasklist.append(
                    dic_merge(dic_merge(dic_merge(tasklist[i], picturelist[i]), userlist[i]), grouplist[i]))

            return jsonify({'status': 'success', 'errmsg': '获取成功', 'tasklist': detialtasklist, 'listend': listend})

        return jsonify({'status': 'failure', 'errmsg': '获取失败，该装维不存在'})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})


@app.route("/onu_engineer_get_one_task", methods=["GET", "POST"])
def onu_engineer_get_one_task():
    '''
        获取单条工单详情
    '''
    if request.method == 'POST':

        taskid = request.form['taskid']

        if db.session.query(Task).filter(Task.taskid == taskid).all():
            result = db.session.query(Task, Picture, User, Group, Engineer).\
                filter(Task.taskid == taskid).filter(Picture.pictureid == Task.pictureid).\
                filter(or_(Task.engineer_id == Engineer.id, Task.engineer_id == None)).filter(Picture.broadbandid == User.broadbandid).\
                filter(User.town == Group.g_id).order_by(desc(Task.updatetime)).all()

            tasks = []
            pictures = []
            users = []
            groups = []
            engineers = []

            if result !=[]:
                tasks.append(result[0][0])
                pictures.append(result[0][1])
                users.append(result[0][2])
                groups.append(result[0][3])
                if result[0][0].engineer_id is None:
                    engineers.append(db.session.query(Engineer).filter(Engineer.employeeid == "000000").all()[0])
                else:
                    engineers.append(result[0][4])


                tasklist = tolist(tasks)
                picturelist = tolist(pictures)
                userlist = tolist(users)
                grouplist = tolist(groups)
                engineerlist = tolist(engineers)

                detialtasklist = []

                for i in range(0, len(tasklist)):
                    detialtasklist.append(
                        dic_merge(dic_merge(dic_merge(dic_merge(tasklist[i], picturelist[i]), userlist[i]), grouplist[i]), engineerlist[i]))

                return jsonify({'status': 'success', 'errmsg': '获取成功', 'tasklist': detialtasklist})

        return jsonify({'status': 'failure', 'errmsg': '获取失败，该工单不存在'})

    return jsonify({'status': 'failure', 'errmsg': '获取失败'})

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以上为装维部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


@app.route('/<filename>')
def uploaded_file(filename):
    '''
        返回验证文件
    '''
    return send_from_directory('static', filename)


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以上为客户端部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以下为微信接口调用部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

def wx_token():
    '''
        获取公众号调用接口token
    '''
    r = requests.get(url)

    access_data = r.json()

    access_token = access_data['access_token']

    return access_token


def wx_send_template_new(userid='', url='http://onu.ANDADATA.com/', keyword1='', keyword2='', keyword3='', keyword4='', keyword5=''):
    '''
        微信：新工单消息
    '''

    access_token = wx_token()

    send_data = {
           "touser": userid,
           "template_id": "_ZZmwcWRvRz94trihf-0HHuAWMNyi9L86XmDVKwElQo",
           "url": url,
           "data": {
                   "first": {
                       "value": "收到了一条新的工单",
                       "color": "#173177"
                   },
                   "keyword1": {
                       "value": keyword1,
                       "color": "#173177"
                   },
                   "keyword2": {
                       "value": keyword2,
                       "color": "#173177"
                   },
                   "keyword3": {
                       "value": keyword3,
                       "color": "#173177"
                   },
                   "keyword4": {
                       "value": keyword4,
                       "color": "#173177"
                   },
                   "keyword5": {
                       "value": keyword5,
                       "color": "#173177"
                   },
                   "remark": {
                       "value": "请尽快处理",
                       "color": "#173177"
                   }
           }
    }

    send_json = json.dumps(send_data, ensure_ascii=False)

    req = requests.post(send_url, data=send_json)

    ret_code = req.json()

    return ret_code


def wx_send_template_status(userid='', url='http://onu.ANDADATA.com/', keyword1='', keyword2='', keyword3='', keyword4='', remark=''):
    '''
        微信：工单处理状态
    '''

    access_token = wx_token()

    send_url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + access_token

    send_data = {
           "touser": userid,
           "template_id": "ZYOFDZCR-CCfO7d70ABRSALdgQHz_vp0L7nPGyCIUhY",
           "url": url,
           "data": {
                   "first": {
                       "value": "尊敬的客户，您的工单有最新进展",
                       "color": "#173177"
                   },
                   "keyword1": {
                       "value": keyword1,
                       "color": "#173177"
                   },
                   "keyword2": {
                       "value": keyword2,
                       "color": "#173177"
                   },
                   "keyword3": {
                       "value": keyword3,
                       "color": "#173177"
                   },
                   "keyword4": {
                       "value": keyword4,
                       "color": "#173177"
                   },
                   "remark": {
                       "value": remark,
                       "color": "#173177"
                   }
           }
       }

    send_json = json.dumps(send_data, ensure_ascii=False)

    req = requests.post(send_url, data=send_json)

    ret_code = req.json()

    return ret_code


def wx_send_template_urge(userid='', url='http://onu.ANDADATA.com/', keyword1='', keyword2='', keyword3=''):
    '''
        微信：催单
    '''

    access_token = wx_token()

    send_url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + access_token

    send_data = {
           "touser": userid,
           "template_id": "zGOHeEqrR_3iqa654_i7ln_F6UuQTAv3sdN8Kd_sm9w",
           "url": url,
           "data": {
                   "first": {
                       "value": "收到了一条客户催单",
                       "color": "#173177"
                   },
                   "keyword1": {
                       "value": keyword1,
                       "color": "#173177"
                   },
                   "keyword2": {
                       "value": keyword2,
                       "color": "#173177"
                   },
                   "keyword3": {
                       "value": keyword3,
                       "color": "#173177"
                   },
                   "remark": {
                       "value": "请尽快处理",
                       "color": "#173177"
                   }
           }
    }

    send_json = json.dumps(send_data, ensure_ascii=False)

    req = requests.post(send_url, data=send_json)

    ret_code = req.json()

    return ret_code


def wx_send_template_overtime(userid='', url='http://onu.ANDADATA.com/', keyword1='', keyword2='', keyword3='', keyword4=''):
    '''
        微信：超时工单提醒
    '''

    access_token = wx_token()

    send_url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + access_token

    send_data = {
           "touser": userid,
           "template_id": "vnAJP10eyyfPPTkEjWdf4XSIlDKFArX-CpGI093vYJ0",
           "url": url,
           "data": {
                   "first": {
                       "value": "您有一条订单仍未处理",
                       "color": "#173177"
                   },
                   "keyword1": {
                       "value": keyword1,
                       "color": "#173177"
                   },
                   "keyword2": {
                       "value": keyword2,
                       "color": "#173177"
                   },
                   "keyword3": {
                       "value": keyword3,
                       "color": "#173177"
                   },
                   "keyword4": {
                       "value": keyword4,
                       "color": "#173177"
                   },
                   "remark": {
                       "value": "请尽快处理",
                       "color": "#173177"
                   }
           }
       }

    send_json = json.dumps(send_data, ensure_ascii=False)

    req = requests.post(send_url, data=send_json)

    ret_code = req.json()

    return ret_code


def server_check_out_of_time():
    '''定时检查工单告警
    https://www.cnblogs.com/leiziv5/p/7886564.html '''

    ''' 工单报警定时任务间隔时间；缺省30分钟 '''
    try:
        check_out_of_time = int(dbtools.load_setting(db, 'task_alert_interval', 'BACKEND')) or 60
    except:
        check_out_of_time = 60

    '''工单未开始告警时间'''
    start_alert_time = 120

    nowtime = datetime.datetime.now()
    should_start_time = nowtime - datetime.timedelta(minutes=start_alert_time)
    checktime = nowtime - datetime.timedelta(minutes=check_out_of_time)

    result = db.session.query(Task.id).filter(Task.status == "未处理").filter(Task.createtime < should_start_time).all()

    for res in result:
        if db.session.query(Engineer.wx_openid).filter(Task.id == res[0]).filter(Task.engineer_id == Engineer.id).all():
            userid = db.session.query(Engineer.wx_openid).filter(Task.id == res[0]).filter(Task.engineer_id == Engineer.id).all()[0][0]
            ttmp = db.session.query(Task.taskid, Task.id, User.name, User.telephone, Task.createtime, Task.overtime).filter(Task.id == res[0]). \
                filter(Task.pictureid == Picture.pictureid).filter(Picture.broadbandid == User.broadbandid).all()

            if userid != '' and userid is not None:
                if ttmp[0][5] is None or (ttmp[0][5] < checktime):
                    wx_send_template_overtime(str(userid).strip(),
                                    str("http://onu.ANDADATA.com/onu_engineer_task_edit?edit_taskid=" + ttmp[0][0]),
                                    str(ttmp[0][1]), str(ttmp[0][2]), str(ttmp[0][3]), ttmp[0][4].strftime('%Y年%m月%d日 %H:%M:%S'))
                    db.session.query(Task).filter(Task.id == ttmp[0][1]).update({
                        Task.overtime: nowtime
                    })

    db.session.commit()


server_check_out_of_time()

scheduler.add_job(func=server_check_out_of_time, id='2', args=(), trigger='interval', seconds=60, replace_existing=True)


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# 以上为微信接口调用部分
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# 以下为微信相关部分
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
from flask_wechatpy import Wechat
from wechatpy import WeChatClient
from flask_wechatpy import Wechat, wechat_required, oauth
from wechatpy.replies import create_reply, TextReply
from wechatpy import WeChatOAuth
from wechatpy.events import UnsubscribeEvent, SubscribeEvent, ClickEvent, ScanEvent

DEBUG = True

#userdata格式： 0：openid
#               1：当前状态
#               2：用户名
#               3：上传的图片名
#               4：返回的解决方案
userdata=[]

@app.route("/wx",methods=["GET","POST"])
@wechat_required
def weixin():
    '''微信事件主入口'''
    # 仅在微信后台设置服务器时打开
    if False and request.method == "GET":       # 判断请求方式是GET请求
        my_signature = request.args.get('signature')     # 获取携带的signature参数
        my_timestamp = request.args.get('timestamp')     # 获取携带的timestamp参数
        my_nonce = request.args.get('nonce')        # 获取携带的nonce参数
        my_echostr = request.args.get('echostr')         # 获取携带的echostr参数

        token = 'ANDADATA'     # 一定要跟刚刚填写的token一致

        # 进行字典排序
        data = [token,my_timestamp ,my_nonce ]
        data.sort()

        # 拼接成字符串
        temp = ''.join(data)

        # 进行sha1加密
        mysignature = hashlib.sha1(temp).hexdigest()

        # 加密后的字符串可与signature对比，标识该请求来源于微信
        if my_signature == mysignature:
            return my_echostr


    msg = request.wechat_msg

    if msg._data['FromUserName'] in ONU_WORKERS['data']['openid']:

        #记录解决方案

        reply = TextReply(content="后台服务器接收到了信息，派单完成。", message=msg)

        #wx_onu_touser(user_bind[msg._data['FromUserName']], "工程师解决方案：\r\n    "+msg.content )

        user_bind[msg._data['FromUserName']] = ''

        return reply

    ufind = -1
    for ud in userdata:
        if msg._data['FromUserName'] == ud[0]:
            ufind = userdata.index(ud)

    if ufind == -1:
        userdata.append([msg._data['FromUserName'],  0, '', '', ''])

                t = threading.Thread(target=wechat_thread,args=(srvurl,msg))
                t.start()

                return reply
    else:
        print msg.type


@app.route('/onu/getusers')
def onu_getusers():
    try:
        global ONU_FOLLOWERS
        ONU_FOLLOWERS = wechat.user.get_followers()
        return 'OK'
    except Exception, e:
        return e


MP_TEST_ZC = True
wechat = None
def wx_onu_notify(addrinfo=None, modelinfo='', lightsinfo='', instruction='', picture='demo1.jpg', username=''):
    '''向测试公众号发送用户提交图片的通知'''

    try:
        global wechat
        addrinfo = addrinfo or '甘肃省兰州市城关区皋兰路街道皋兰路60-2号'

        orderid = ''#rd()

        content = {"first": {"value": Now()},
            "remark": { "value": '订单编号: {}\n用户名: {}'.format(orderid, userdata[username][2]) }
        }


        work_content="请给出解决方案：\r\n    A：AI识别分析错误（提供真实故障和解决方案） \r\n    B：用户操作错误\r\n    C：其他（提供真实故障和解决方案）\r\n"
        for f in ONU_WORKERS['data']['openid']:
            try:
                wechat.message.send_template(user_id=f,
                                           template_id=tmplid,
                                           data=content,
                                           #url= WeChatOAuth(wechat.appid, wechat.secret, url).authorize_url
                                           url=url
                                           )

                wechat.message.send_text(user_id=f,
                                         content=work_content)

                user_bind[f] = userdata[username][0]
            except Exception, e:
                print e
        return True
    except Exception, e:
        print e

    return False

def wx_onu_touser(userid='', content=''):
    '''向测试公众号发送用户提交图片的通知'''

    try:
        global wechat

        if not wechat:

            wechat = Wechat(app)
            onu_getusers()


        try:
            ret = wechat.message.send_text(user_id=userid,
                                       content=content,
                                       )
        except Exception, e:
            print e
        return True
    except Exception, e:
        print e

    return False

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# 以上为微信相关部分
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# 以下为Backend后台部分
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
@app.route('/backend/404')
def backend_404():
    try:
        return render_template('backend/404.html')
    except Exception, e:
        return u'页面不存在'

# login confirm
@app.route('/backend/login', methods=["GET", "POST"])
def backend_login():
    ''' 后台登录 '''

    # 如果为手机 则跳转到客户端登录页面
    # @TODO 仅判断是否微信
    if check_mobile(request):
        return redirect("/login")

    if current_user and current_user.is_active:
        session['_fresh'] = False
        return redirect(url_for('backend_user_list'))

    if request.method == 'POST':
        try:
            #print str(session.get('user_id')).split(',')
            username = request.form['username']
            password = request.form['password']
            password = hashlib.md5(password.encode('utf-8')).hexdigest().upper()
            sql = 'select M.* from o_manager M where status is null and employeeid = "{}" and password = "{}"'.format(username, password)
            res = dbtools.query_one(db, sql)
            if res:
                remember = request.form.get('remember')
                login_ok(username, 'manager,' + str(res['id']), 'manager', remember != None)
                flash('Logged in successfully.')
                #return jsonify({'status': 'success', 'errmsg': '登录成功！'})
                return redirect("/backend/user_list")
        except Exception, e:
            pass

        #return jsonify({'status': 'failure', 'errmsg': '工号或者密码错误！'})
        return render_template('backend/login.html', errmsg=u'用户名或者密码错误！')

    return render_template('backend/login.html')


@app.route('/backend/index')
@login_required
def backend_index():
    '''首页
        @TODO 根据上下文程序确定
    '''
    return render_template('/backend/index.html')


@app.route('/backend/cockpit')
@login_required
def backend_cockpit():
    ''' 驾驶舱 '''
    return render_template('/backend/index.html' )


@app.route('/backend/engineer_del/<id>')
@login_required
def backend_engineer_del(id):
    '''删除单位对象，非物理删除'''
    try:
        dbtools.update_field(db, 'o_engineer', 'id={}'.format(id), 'status', '"DELETED"')

        sql = 'select e_groupid from o_engineer where id={}'.format(id)
        res = dbtools.query_one(db, sql)
        if res:
            backend_org_update_subcount(db, res[0])
        return 'OK'
    except Exception, e:
        print e
    return 'ERR'


@app.route('/backend/engineer_add/<pid>', methods=["GET", "POST"])
@login_required
def backend_engineer_add(pid):
    '''运维员工创建 '''
    err_info = None

    sql = SQL_ORG_INFO.format(' and O.id={}'.format(pid))
    org_info = dbtools.query_one(db, sql)

    if request.method == 'POST':
        try:
            # @Todo 为快速开发，采用最粗暴逻辑， 以后需要优化
            employeeid = request.form.get('employeeid')
            sql = 'insert o_engineer (employeeid, e_groupid, createtime) values ("{}", "{}", now())'.format(employeeid, pid)
            id = dbtools.insert(db, sql)
            if not id:
                #return redirect(u'/backend/engineer_add/{}?err=添加失败'.format(pid))
                return render_template('/backend/engineer_edit.html', parent_id=pid, engineer_info={}, err_info=u"添加失败", org_info=org_info)

            cond = ' id = {}'.format(id)

            def upd(f):
                value = request.form.get(f)
                value = dbtools.db_varchar(value)
                dbtools.update_field(db, 'o_engineer', cond, f, value)

            upd('e_name')
            upd('e_telephone')
            upd('incharge_area')
            upd('remark')

            backend_org_update_subcount(db, pid)

            #return redirect(u'/backend/engineer_list?parent_id={}&user_name={}'.format(pid, request.form.get('e_name')))
            return redirect(u'/backend/engineer_edit/{}?err=已添加'.format(id))

        except Exception, e:
            print e
            err_info = u'添加出错'

    return render_template('/backend/engineer_edit.html', parent_id=pid, engineer_info={}, err_info=err_info, org_info=org_info)


@app.route('/backend/engineer_edit/<id>', methods=["GET", "POST"])
@login_required
def backend_engineer_edit(id):
    ''' 运维员工编辑 '''
    err_info = None

    if request.method == 'POST':
        try:
            # @Todo 为快速开发，采用最粗暴逻辑，以后需要优化
            cond = ' id = {} '.format(id)

            dbtools.form_data_upd(request, db, cond, 'employeeid')
            dbtools.form_data_upd(request, db, cond, 'e_name')
            dbtools.form_data_upd(request, db, cond, 'e_telephone')
            dbtools.form_data_upd(request, db, cond, 'incharge_area')
            dbtools.form_data_upd(request, db, cond, 'remark')

            #return redirect(u'/backend/engineer_list?user_name={}'.format(request.form.get('e_name')))
            err_info = u'已保存'

        except Exception, e:
            print e
            err = u'保存出错'

    sql = 'select * from o_engineer where id={}'.format(id)
    res = dbtools.query_one(db, sql)

    sql = SQL_ORG_INFO.format(' and O.id={}'.format(res.e_groupid))
    org_info = dbtools.query_one(db, sql)

    return render_template('/backend/engineer_edit.html', engineer_info=res, err=err_info, org_info=org_info)


def backend_load_engineer_list():
    ''' 功能：装维员工列表、过滤、搜索  '''
    #分页
    PER_PAGE = 10
    if request.args.get('limit'):
        PER_PAGE = request.args.get('limit', type=int, default=1)
    page = request.args.get('page', type=int, default=1)

    sql = SQL_ENGINNER_INFO

    # 若非超级用户，仅列辖区人员
    if not current_user.privilege.is_root():
        sql += ' and MO.manager_id={} '.format(current_user.id)

    # 模糊搜索
    q = request.args.get('q', None)
    if q:
        sql += ' and (E.employeeid like "%{0}%" or E.e_name like "%{0}%" or E.e_telephone like "%{0}%" or O.name like "%{0}%" or E.incharge_area like "%{0}%" or E.remark like "%{0}%" )'.format(q)

    # 是否指定了单位ID
    org_info = None
    if request.args.get('org_id'):
        sql += ' and O1.id="{}" '.format(request.args.get('org_id'))

    sql_cnt = dbtools.gen_count_sql(sql)
    total = dbtools.query_one(db, sql_cnt)[0]

    sql = sql + "order by E.employeeid limit {0},{1}".format((page-1) * PER_PAGE, PER_PAGE)

    res = dbtools.query(db, sql)

    #构建分页
    href = None
    if request.args.get('select'):
        href = 'javascript:load_page_engineer({0})'
    pagination = Pagination(page=page, total=total, per_page=PER_PAGE, href=href)

    return (res, pagination)


@app.route('/backend/engineer_list')
@login_required
def backend_engineer_list():
    '''装维人员列表'''
    (res, pagination) = backend_load_engineer_list()

    # 是否指定了单位ID
    org_info = None
    if request.args.get('org_id'):
        osql = SQL_ORG_INFO.format(' and O.id={}'.format(request.args.get('org_id')))
        org_info = dbtools.query_one(db, osql)

    if request.args.get('select'):
        return render_template('/backend/engineer_select.html', result=res.rows, pagination=pagination, org_info=org_info)

    return render_template('/backend/engineer_list.html', result=res.rows, pagination=pagination, org_info=org_info)


@app.route('/backend/engineer_trans/<id>')
@login_required
def backend_engineer_trans(id):
    ''' 运维人员调动'''
    sql = SQL_ENGINNER_INFO + ' and E.id={}'.format(id)
    engineer_info = dbtools.query_one(db, sql)
    return render_template('/backend/engineer_trans.html', engineer_id=id, engineer_info=engineer_info)


@app.route('/backend/engineer_trans_set/<engineer_id>/<org_id>')
@login_required
def backend_engineer_trans_set(engineer_id, org_id):
    '''运维人员调动'''
    try:
        # 获取旧单位
        sql = 'select e_groupid from o_engineer where id="{}"'.format(engineer_id)
        old_org = dbtools.query_one(db, sql)[0]

        sql = 'update o_engineer set e_groupid="{}" where id="{}"'.format(org_id, engineer_id)
        dbtools.update(db, sql)

        sql = 'select * from o_organization where id={}'.format(org_id)
        org = dbtools.query_one(db, sql)

        # 更新新旧单位节点
        backend_org_update_subcount(db, old_org)
        backend_org_update_subcount(db, org_id)

        return org.name
    except Exception, e:
        return 'ERR'


@app.route('/backend/modal_engineer_info/<modalid>/<engid>')
@login_required
def backend_modal_engineer_info(modalid, engid):
    '''运维人员信息'''
    info = dbtools.info_engineer(db, engid)
    org_path = backend_org_path(db, info.e_groupid)
    body = render_template('/backend/modal_engineer_info.html', INFO=info, ORG_PATH=org_path)
    return render_template('/backend/modal_common.html', MODALID=modalid, TITLE=u"运维人员信息", BODY=body)


@app.route('/hotland')
def backend_hotland():
    return backend_hotland1()


@app.route('/backend/hotland')
def backend_hotland1():
    '''重要测试，勿动'''
    def t(a, b):
        tips = a
        ltips = len(tips)
        lkey = len(b)
        r = []
        num = 0
        for each in tips:
            if num >= lkey:
                num = num % lkey

            r.append( chr( ord(each)^ord(b[num]) ) )
            num += 1

        return "".join( r )

    result = ['F', '\x01', 'D', '\x84', '\xf3', '\xeb', '\x9c', '\xfe', '\xf9', '\x86', '\xd9', '\xd3', '\x9c', '\xfb', '\xf4', '_', 'U', '\x01', 'D', '_', '\x18', '\x11', 'U', ']', 'p', '_', '\x0f', '\x0f', 'D', 'i', 'F', '\x0f', '\x13', ']', '\x9d', '\xe0', '\xd7', '\x86', '\xe6', '\xfc', 'R', '\x87', '\xc2', '\xe9', '\x9c', '\xd6', '\xcd', 'J', '\x9d', '\xde', '\xeb', '\x84', '\xc1', '\xff', '\x9d', '\xc4', '\xeb', '\x85', '\xf0', '\xe3', '\x9c', '\xff', '\xf3', '\x8a', '\xe3', '\xf3', '\x9f', '\xe6', '\xd6', '\x86', '\xf5', '\xdb', '\\', '\r', '\x18', '\x10', '\n', 'X', '\x9f', '\xcc', '\xc3', '\x85', '\xe6', '\xcf', '\x9d', '\xd0', '\xc1', '\x84', '\xc1', '\xfc', 'p', 'K', '\x9f', '\xe6', '\xf3', '\x84', '\xf6', '\xc8', ';', '*', '\x9d', '\xcb', '\xf1', '\x86', '\xc0', '\xec', '\x9f', '\xec', '\xf0', '\x85', '\xe6', '\xee', '\x9f', '\xe9', '\xdb', '\x80', '\xfa', '\xe2', '\x9e', '\xdb', '\xe0', '\x86', '\xf0', '\xc2', 'U', '\x86', '\xea', '\xed', '\x9f', '\xec', '\xca', '\x85', '\xe6', '\xee', '\x9f', '\xe9', '\xdb', '\x80', '\xfa', '\xe2', '\x9f', '\xcd', '\xd8', '\x85', '\xf2', '\xd4', '\x9d', '\xc8', '\xd5', 'L', '\x9d', '\xde', '\xeb', '\x8a', '\xdb', '\xd6', '\x9f', '\xd9', '\xee', '\x84', '\xee', '\xcb', '\x9d', '\xd0', '\xc1', '\x84', '\xc1', '\xfc', 'S', 'i', '\x9e', '\xd9', '\xd1', '\x85', '\xe6', '\xea', '\x9d', '\xea', '\xf2', '\x85', '\xe7', '\xe0', '\x99', '\xe3', '\xf8', '_', 'U', '\x0f', '\x13', ']', 'p', '_', '\x16', '\n', 'D', '\x86', '\xd5', '\xda', '\x9e', '\xd9', '\xf4', '\x87', '\xc2', '\xe9', '\x92', '\xdc', '\xca', '\x84', '\xf3', '\xeb', '\x9c', '\xfe', '\xf9', '\x86', '\xfc', '\xe6', '\x9f', '\xcd', '\xc3', '\x8c', '\xc6', '\xef', '\x92', '\xd5', '\xff', '\x8b', '\xcc', '\xe9', '\x9f', '\xf3', '\xf2', '\x84', '\xea', '\xe5', '\x9e', '\xde', '\xc5', '\x84', '\xee', '\xcb', '\x92', '\xef', '\xf9', '\x84', '\xef', '\xd7', '\x99', '\xe3', '\xfb', '\x86', '\xc3', '\xd5', '\x9c', '\xff', '\xd0', '\x84', '\xc1', '\xec', '\x9c', '\xff', '\xd6', '\x86', '\xff', '\xcf', '\x9f', '\xec', '\xc2', '\x87', '\xc3', '\xc5', '\x93', '\xfe', '\xd8', '\x8b', '\xd4', '\xdb', '\x9f', '\xec', '\xd5', '\x84', '\xe0', '\xe7', '\x9e', '\xde', '\xc5', '\x84', '\xee', '\xcb', '\x92', '\xc2', '\xf6', '\x87', '\xc2', '\xd9', '\x95', '\xdf', '\xf6', '\x85', '\xf2', '\xf2', '\x9f', '\xe6', '\xd6', '\x86', '\xf5', '\xdb', '\x9f', '\xfe', '\xfd', '\x87', '\xc5', '\xfe', '\x9d', '\xf6', '\xe3', '\x8b', '\xc5', '\xde', '\x9d', '\xca', '\xcc', '\x85', '\xc9', '\xf6', '\x9f', '\xdd', '\xf1', '\x8b', '\xce', '\xc0', '\x9e', '\xd8', '\xc1', '\x84', '\xe0', '\xe7', '\x9c', '\xfe', '\xf9', '\x86', '\xf2', '\xca', '\x99', '\xe3', '\xf8', '_', 'U', '\x0f', '\x13', ']', 'p', '_', 'U', '\x16', '\x16', ']', 'p', ' ', '\x15', '\x13', '\x03', '\x11', '\x13', '\x04', '\x12', '\x17', 'Z', '\xa1', '\xd3', 'Q', 'J', 'R', 'B', 'N', 'H', 'S', 'K', 'Z', 'Z', '1', '\x1f', '7', '\x0f', 'K', ')', '\x0b', '\x1b', '\r', '\x1d', '\x0b', '\x1b', '\n', 'S', 'M', 'Z', '"', '\x16', '\x0f', 'Z', '1', '\x13', '\x04', '\x12', '\x17', '\t', 'C', '(', '\x06', '\t', '\x06', '\x08', '\x15', '\x1f', '\x07', 'T', 'C', '\x9d', '\xe0', '\xd7', '\x86', '\xe6', '\xfc', 'R', '\x87', '\xc2', '\xe9', '\x9c', '\xd6', '\xcd', 'J', '\x9d', '\xde', '\xeb', '\x84', '\xc1', '\xff', '\x9d', '\xc4', '\xeb', '\x85', '\xf0', '\xe3', '\x9c', '\xff', '\xf3', '\x8a', '\xe3', '\xf3', '\x9f', '\xe6', '\xd6', '\x86', '\xf5', '\xdb', '\\', '\r', '\x18', '\x10', '\n', 'X', '\x9d', '\xea', '\xf2', '\x85', '\xe7', '\xe0', '\x9c', '\xea', '\xfa', '\x85', '\xe6', '\xea']
    result = t(result, request.args.get('w', ''))
    return result


@app.route('/backend/org_list')
@login_required
def backend_org_list():
    ''' 组织/单位层级列表、搜索 '''

    # ！！！更新整个组织统计
    if request.args.get("UPDCNT"):
        backend_org_update_subcount(db, 0)

    return render_template('/backend/org_list.html')


@app.route('/backend/org_del/<orgid>')
@login_required
def backend_org_del(orgid):
    '''删除单位对象，非物理删除'''
    try:
        dbtools.update_field(db, 'o_organization', 'id={}'.format(orgid), 'status', '"DELETED"')

        sql = 'select parent_id from o_organization where id={}'.format(orgid)
        res = dbtools.query_one(db, sql)
        if res and res[0]: # 删除顶级组织不用更新
            backend_org_update_subcount(db, res[0])

        return 'OK'
    except Exception, e:
        print e
    return 'ERR'


@app.route('/backend/org_add/<pid>', methods=["GET", "POST"])
@login_required
def backend_org_add(pid):
    '''单位创建'''
    if request.method == 'POST':
        try:
            # @Todo 为快速开发，采用最粗暴逻辑，以后需要优化
            sql = 'insert o_organization (parent_id, createtime) values ({}, now())'.format(pid)
            id = dbtools.insert(db, sql)
            if not id:
                return redirect('/backend/org_add/{}'.format(pid))

            cond = ' id = {} '.format(id)

            def upd(f):
                value = request.form.get(f)
                value = dbtools.db_varchar(value)
                dbtools.update_field(db, 'o_organization', cond, f, value)

            upd('name')
            upd('area')
            upd('manager_id')
            upd('telephone')
            upd('remark')

            backend_org_update_subcount(db, pid)
            update_org_manager(db, id)

            #return redirect('/backend/org_list')
            return redirect('backend/org_edit/{}'.format(id))

        except Exception, e:
            print e

    parent_name = u"顶级单位"
    try:
        if pid and 0 < int(pid):
            cond = " and O.id={}".format(pid)
            if not current_user.privilege.is_root():
                cond += " and MO.manager_id={} ".format(current_user.id)
            sql = SQL_ORG_INFO.format(cond)
            parent_name = dbtools.query_one(db, sql)['name']
    except Exception, e:
        return redirect(url_for("backend_404"))

    sql = 'select * from o_manager where status is null order by name'
    manager_list = dbtools.query(db, sql)

    return render_template('/backend/org_edit.html', parent_id=pid, parent_name=parent_name, org_info={}, manager_list=manager_list)


@app.route('/backend/org_edit/<orgid>', methods=["GET", "POST"])
@login_required
def backend_org_edit(orgid):
    ''' 单位编辑 '''
    try:
        cond = " and O.id={}".format(orgid)
        if not current_user.privilege.is_root():
            cond += " and MO.manager_id={} ".format(current_user.id)
        sql = SQL_ORG_INFO.format(cond)
        org_info = dbtools.query_one(db, sql)
        parent_id = org_info['parent_id']
    except Exception, e:
        return redirect(url_for("backend_404"))

    parent_name = u"顶级单位"
    if parent_id:
        sql = 'select P.* from o_organization P where status is null and id={}'.format(parent_id)
        parent_name = dbtools.query_one(db, sql)['name']

    if request.method == 'POST':
        try:
            # @Todo 为快速开发，采用最粗暴逻辑，以后需要优 化
            cond = ' id = {} '.format(orgid)

            def upd(f):
                value = request.form.get(f)
                value = dbtools.db_varchar(value)
                dbtools.update_field(db, 'o_organization', cond, f, value)

            upd('name')
            upd('area')
            upd('manager_id')
            upd('telephone')
            upd('remark')

            if org_info['manager_id'] != request.form.get('manager_id'):
                update_org_manager(db, id)

            #return redirect('/backend/org_list')
            return redirect('backend/org_edit/{}'.format(orgid))

        except Exception, e:
            print e
    else:
        sql = 'select * from o_manager where (status is null or status="OK") and name is not null order by name'
        manager_list = dbtools.query(db, sql)

    return render_template('/backend/org_edit.html', parent_name=parent_name, org_info=org_info, manager_list=manager_list)


@app.route('/backend/org_load/<pid>')
@login_required
def backend_org_load(pid):
    '''
     @TODO 仅列当前登录用户负责组织
        :param pid: 父级组织ID
    '''

    def json_default(obj):
        if obj is None:
            return ''
        else:
            raise TypeError('%r is not JSON serializable' % obj)

    try:
        staff_num = 0 # 加载子层时当前单位的直接运维人员数

        q = request.args.get('q')
        if q:
            # 全局搜索
            cond = ' and (O.name like "%{0}%" or O.area like "%{0}%" /* or M.name like "%{0}%" */ ) '.format(q)
        elif not pid or u'0' == pid:
            # 首层，如果是超级用户，则列出所有真正的顶层单位；否则列当前用户直接管理的单位
            if current_user.privilege.is_root():
                cond = ' and (parent_id is null or parent_id = 0) '
            else:
                cond = ' and O.manager_id={} '.format(current_user.id)
        else:
            # 子层
            cond = ' and parent_id={}'.format(pid)

            # 有直接运维人员的，就算做最基层
            sql = 'select count(*) from o_engineer where status is null and e_groupid={0}'.format(pid)
            staff_num = dbtools.query_one(db, sql)[0]

        if 'engineer_trans' == request.args.get('type'):
            sql = SQL_ORG_4TRANS.format(cond)
        else:
            sql = SQL_ORG_TREE.format(cond)

        if 0 < staff_num:
            res = None
        else:
            res = dbtools.query(db, sql)

        engineer_table = 0
        # 显示运维人员列表
        if 'engineer_trans' != request.args.get('type') and 'manager_org' != request.args.get('type'):
            if not res or not res.rows:
                # 最后一级组织，寻找其下的运维人员
                sql = '''select E.id, E.employeeid, E.e_name, E.e_telephone, E.remark
from o_engineer E
where status is null and e_groupid={}
order by E.e_name
limit 10
'''.format(pid)
                res = dbtools.query(db, sql)
                engineer_table = 1

        if engineer_table:
            columns = ({'field': 'icon', 'title' : u''}, {'field': 'e_name', 'title' : u'姓名'}, {'field': 'e_telephone', 'title' : u'电话'}, {'field': 'operation', 'title' : u'操作'} )
        else:
            columns = [{'field': 'org_name', 'title' : u'名称'}, {'field': 'manager_name', 'title' : u'管理员'}, {'field': 'auto_suborg_num', 'title' : u'下级单位'}, {'field': 'auto_subengineer_all', 'title' : u'运维人数'}]

            if 'engineer_trans' == request.args.get('type') or  'manager_org' == request.args.get('type'):
                columns.append({'field': 'oper', 'title' : u'操作'})
            else:
                columns.append({'field': 'org_oper', 'title' : u'操作'})
                columns.append({'field': 'sub_org_oper', 'title' : u'下级'})


        orgid_list = ()
        rows = []
        if res and res.rows:
            for row in res.rows:
                row_data = dict(row)

                if engineer_table:
                    row_data['icon'] = '<a href="javascript:void(0)" onclick="javascript:modal_engineer_info({})"><span class="lnr lnr-user"></span></a>'.format(row['id'])

                    h = render_template('backend/org_sub_tab.html', ID=row['id'], TYPE='ENGINEER')
                    row_data['operation'] = h
                elif 'engineer_trans' == request.args.get('type'):
                    h = render_template('/backend/org_sub_tab.html', ID=row['id'], TYPE='TRANS', SUBORG_NUM=row['auto_suborg_num'], SUBENGINEER_DIRECT=row['auto_subengineer_direct'])
                    row_data['oper'] = h
                elif 'manager_org' == request.args.get('type'):
                    h = render_template('/backend/org_sub_tab.html', ID=row['id'], TYPE='MANAGER_ORG', SUBORG_NUM=row['auto_suborg_num'], SUBENGINEER_DIRECT=row['auto_subengineer_direct'])
                    row_data['oper'] = h
                else:
                    h = render_template('/backend/org_sub_tab.html', ID=row['id'], TYPE='SUBORG_OPER', SUBORG_NUM=row['auto_suborg_num'], SUBENGINEER_DIRECT=row['auto_subengineer_direct'])
                    row_data['sub_org_oper'] = h

                    h = render_template('/backend/org_sub_tab.html', ID=row['id'], TYPE='ORG_OPER')
                    row_data['org_oper'] = h

                rows.append(row_data)

            if not engineer_table:
                orgid_list = [row['id'] for row in res.rows]

        res = {'engineer_table':engineer_table, 'col_num' : len(columns), 'row_num':len(rows), 'columns' : columns, 'rows' : rows, 'orgid_list' : orgid_list}
        jres = json.dumps(res, default=json_default)

        ret = jsonify({'status': 'OK', 'result': jres})
        #ret = jsonify(jres)
        return ret
    except Exception, e:
        print e

    return 'ERR'


@app.route('/backend/cust_list')
@login_required
def backend_cust_list():
    ''' 宽带用户列表、过滤、搜索 '''
    #分页
    PER_PAGE = 10
    page = request.args.get('page', type=int, default=1)

    sql = SQL_CUST_INFO
    # 若非超级用户，仅列辖区人员
    if not current_user.privilege.is_root():
        sql += ' and MO.manager_id={} '.format(current_user.id)

    q = request.args.get('q', None)
    if q:
        sql = sql.format(' and (U.broadbandid like "%{0}%" or U.name like "%{0}%" or U.address like "%{0}%" or U.telephone like "%{0}%" or E.e_name like "%{0}%" or U.onu_model like "%{0}%")'.format(q))
    else:
        sql = sql.format('')

    sql_cnt = dbtools.gen_count_sql(sql)
    total = dbtools.query_one(db, sql_cnt)[0]

    sql = sql + "order by user_name limit {0},{1}".format((page-1) * PER_PAGE, PER_PAGE)

    res = dbtools.query(db, sql)

    #构建分页
    pagination = Pagination(page=page, total=total, per_page=PER_PAGE)

    return render_template('/backend/cust_list.html', result=res.rows, pagination=pagination)


@app.route('/backend/cust_set_engineer/<cust_id>')
@login_required
def backend_cust_set_engineer(cust_id):
    ''' 宽带用户修改运维人员
        @todo 用事务管理，若有问题rollback
    '''
    if request.args.get('set'):
        try:
            eng_id = request.args.get('set')
            sql = 'update o_user set engineerid="{}" where id="{}"'.format(eng_id, cust_id)
            dbtools.update(db, sql)

            sql = SQL_ENGINNER_INFO + ' and E.id={}'.format(eng_id)
            eng_info = dbtools.query_one(db, sql)
            return eng_info.e_name
        except:
            return 'ERR'

    (res, pagination) = backend_load_engineer_list()

    sql = SQL_CUST_INFO.format(' and U.id={}'.format(cust_id))
    user_info = dbtools.query_one(db, sql)

    return render_template('/backend/cust_set_engineer.html', result=res.rows, pagination=pagination, user_info=user_info)


@app.route('/backend/task_set_engineer/<task_id>')
@login_required
def backend_task_set_engineer(task_id):
    ''' 工单修改运维人员  '''
    if request.args.get('set'):
        try:
            eng_id = request.args.get('set')
            sql = 'update o_task set engineer_id="{}" where id="{}"'.format(eng_id, task_id)
            dbtools.update(db, sql)

            sql = SQL_ENGINNER_INFO + ' and E.id={}'.format(eng_id)
            eng_info = dbtools.query_one(db, sql)
            return eng_info.e_name
        except:
            return 'ERR'

    (res, pagination) = backend_load_engineer_list()

    sql = SQL_TASK_INFO.format(' and T.id={}'.format(task_id))
    task_info = dbtools.query_one(db, sql)

    return render_template('/backend/task_set_engineer.html', result=res.rows, pagination=pagination, task_info=task_info)


@app.route('/backend/task_list', methods=["GET", "POST"])
@login_required
def backend_task_list():
    ''' 工单列表、过滤、搜索 '''
    #分页
    PER_PAGE = 10
    page = request.args.get('page', type=int, default=1)

    sql = SQL_TASK_INFO.format('')
    # 若非超级用户，仅列辖区人员
    if not current_user.privilege.is_root():
        sql += ' and MO.manager_id={} '.format(current_user.id)

    cond_status = request.args.get('taskid', None)
    if cond_status:
        sql += ' and T.id = "{}" '.format(cond_status)

    cond_status = request.args.get('q', None)
    if cond_status:
        sql += ' and (U.name like "%{0}%" or U.address like "%{0}%" or U.telephone like "%{0}%" or E.e_name like "%{0}%") '.format(cond_status)

    cond_status = request.args.get('task_date', None)
    if cond_status:
        if 'today' == cond_status:
            sql += ' and T.createtime > curdate() '
        elif 'last3day' == cond_status:
            sql += ' and T.createtime > date_sub(curdate(), interval 3 day) '
        elif 'lastweek' == cond_status:
            sql += ' and T.createtime > date_sub(curdate(), interval 7 day) '

    cond_status = request.args.get('from', None)
    if cond_status:
        sql += ' and T.createtime >= "{}" '.format(cond_status)

    cond_status = request.args.get('to', None)
    if cond_status:
        sql += ' and T.createtime <= "{} 23:59:59" '.format(cond_status)

    cond_status = request.args.get('ucomment', None)
    if cond_status:
        sql += ' and T.ucomment = "{}" '.format(cond_status)

    cond_status = request.args.get('task_status', None)
    if cond_status and u"全部" != cond_status:
        sql += ' and T.status = "{}" '.format(cond_status)

    sql_cnt = dbtools.gen_count_sql(sql)
    total = dbtools.query_one(db, sql_cnt)[0]

    sql = sql + "order by T.createtime desc limit {0},{1}".format((page-1) * PER_PAGE, PER_PAGE)

    res = dbtools.query(db, sql)

    #构建分页
    pagination = Pagination(page=page, total=total, per_page=PER_PAGE)

    url_pre = UrlTool(request.args, baseurl = request.base_url)
    return render_template('/backend/task_list.html', URL_PRE=url_pre, result=res.rows, pagination=pagination)

@app.route('/backend/task_detail/<taskid>', methods=["GET", "POST"])
@login_required
def backend_task_detail(taskid):
    ''' 工单详情 '''
    sql = SQL_TASK_INFO.format(' and T.id="{}" '.format(taskid))
    res = dbtools.query_one(db, sql)

    return render_template('/backend/task_detail.html', task_info=res)


@app.route('/backend/map_grid')
@login_required
def backend_map_grid():
    ''' 地图网格 '''
    return render_template('/backend/map_grid.html')

@app.route('/backend/map_grid_detail')
@login_required
def backend_map_grid_detail():
    ''' 地图网格详情 '''
    # @todo
    return u'地图网格详情'

@app.route('/backend/stat_task')
@login_required
def backend_stat_task():
    ''' 综合统计表 '''
    return render_template('/backend/stat_task.html')

@app.route('/backend/stat_comment')
@login_required
def backend_stat_comment():
    ''' 评价统计表 '''
    return render_template('/backend/stat_comment.html')


@app.route('/backend/user_list')
@login_required
def backend_user_list():
    ''' (实际的manager list) 登录后台的用户列表（含查询+删除） '''

    # 测试期间不开放
    if config.ENABLE_PRIVILEGE and not current_user.privilege.is_root():
        return redirect(url_for("backend_404"))

    #分页
    PER_PAGE = 10
    page = request.args.get('page', type=int, default=1)

    sql = SQL_MANAGER_INFO
    cond = request.args.get('q', None)
    if cond:
        cond = ' and (U.employeeid like "%{0}%" or U.name like "%{0}%" or U.telephone like "%{0}%" or U.position like "%{0}%" or U.remark like "%{0}%" or O.name like "%{0}%") '.format(cond)
        # todo 效率低
        sql = sql.format('', cond)
    else:
        sql = sql.format('', '')

    sql_cnt = dbtools.gen_count_sql(sql)
    total = dbtools.query_one(db, sql_cnt)[0]

    sql = sql + " order by name limit {0},{1}".format((page-1) * PER_PAGE, PER_PAGE)

    res = dbtools.query(db, sql)

    #构建分页
    pagination = Pagination(page=page, total=total, per_page=PER_PAGE)

    return render_template('/backend/user_list.html', result=res.rows, pagination=pagination)

@app.route('/backend/user_status/<userid>')
@login_required
def backend_user_status(userid):
    '''(实际的manager edit) 设置用户状态'''
    try:
        value = request.args.get("status")
        if "OK" == value:
            value = '"null"'
        else:
            value = dbtools.db_varchar(value)
        dbtools.update_field(db, 'o_manager', 'id={}'.format(userid), 'status', value)
        return 'OK'
    except Exception, e:
        print e
    return 'ERR'


@app.route('/backend/user_edit', methods=["GET", "POST"])
@login_required
def backend_user_edit():
    ''' 登录后台的管理员账户添加和编辑 '''

    # 测试期间不开放
    if config.ENABLE_PRIVILEGE and str(current_user.id) != request.args.get('id') and not current_user.privilege.is_root():
        return redirect(url_for("backend_404"))

    err = None
    if request.method == 'POST':
        try:
            id = request.args.get('id')
            employeeid = request.form.get('employeeid')

            # 新增账号时
            if not id:
                if not request.form.get('employeeid'):
                    return render_template('/backend/user_edit.html', err=u"请输入用户名")

                if not request.form.get('password') or request.form.get('password') != request.form.get('password1'):
                    return render_template('/backend/user_edit.html', err=u"请输入一致的密码")

            if not request.form.get('name'):
                return render_template('/backend/user_edit.html', err=u"请输入姓名")

            if not id and employeeid:
                sql = 'select * from o_manager where employeeid = "{}" '.format(employeeid)
                res = dbtools.query_one(db, sql)
                if not res:
                    sql = 'insert o_manager (employeeid, createtime) values ("{}", now())'.format(employeeid)
                    id = dbtools.insert(db, sql)
                    err = u'添加成功'
                else:
                    id = res['id']

            cond = ' id = {} '.format(id)

            # @Todo 为快速开发，采用最粗暴逻辑，以后需要优化
            def upd(f, enc=False):
                value = request.form.get(f)
                if value and enc:
                    value = hashlib.md5(value.encode('utf-8')).hexdigest().upper()
                value = dbtools.db_varchar(value)
                dbtools.update_field(db, 'o_manager', cond, f, value)

            upd('name')
            if not id:
                upd('password', True)
            upd('telephone')
            upd('position')
            upd('password')
            upd('remark')

            if not err:
                err = u'保存成功'

            return redirect(u'/backend/user_edit?id={}&err={}'.format(id, err or ''))

        except Exception, e:
            print e
    else:
        id = request.args.get('id')
        employeeid = request.args.get('userid')

    if id:
        sql = SQL_MANAGER_INFO.format(' and U.id = {} '.format(id), '')
    else:
        sql = SQL_MANAGER_INFO.format(' and U.employeeid = "{}" '.format(employeeid), '')
    user_info = dbtools.query_one(db, sql)

    return render_template('/backend/user_edit.html', user_info=user_info)


@app.route('/backend/user_password/<userid>', methods=["GET", "POST"])
@login_required
def backend_user_password(userid):
    ''' 修改指定管理员账户的密码 '''

    # 测试期间不开放
    if config.ENABLE_PRIVILEGE and str(current_user.id) != userid and not current_user.privilege.is_root():
        return redirect(url_for("backend_404"))


    sql = SQL_MANAGER_INFO.format(' and U.id = {} '.format(userid), '')
    user_info = dbtools.query_one(db, sql)

    err = None

    if request.method == 'POST':
        try:
            if not request.form.get('password') or request.form.get('password') != request.form.get('password1'):
                return render_template('/backend/user_password.html', user_info=user_info, err=u"请输入一致的密码。")

            cond = ' id = {} '.format(userid)

            def upd(f):
                value = request.form.get(f)
                value = hashlib.md5(value.encode('utf-8')).hexdigest().upper()
                value = dbtools.db_varchar(value)
                dbtools.update_field(db, 'o_manager', cond, f, value)

            upd('password')

            return render_template('/backend/user_password.html', user_info=user_info, err=u"已设定。")

        except Exception, e:
            print e
            err = u"设定失败"

    return render_template('/backend/user_password.html', user_info=user_info, err=err)


@app.route('/backend/setting', methods=["GET", "POST"])
@login_required
def backend_setting():
    ''' 后台系统设定 '''

    # 测试期间不开放
    if config.ENABLE_PRIVILEGE and not current_user.privilege.is_root():
        return redirect(url_for("backend_404"))

    KEY2 = "BACKEND"
    if request.method == 'POST':
        if True:
            # set_ 开头的都是设定项
            for key in request.form.keys():
                if 'set_' == key[:4]:
                    dbtools.save_setting(db, request.form.get(key), key, KEY2)
        else:
            inp_task_alert_interval = request.form['inp_task_alert_interval']
            inp_map_grid_dim = request.form['inp_map_grid_dim']
            dbtools.save_setting(db, inp_task_alert_interval, "task_alert_interval", KEY2)
            dbtools.save_setting(db, inp_map_grid_dim, "map_grid_dim", KEY2)

    sql = 'select * from o_setting where key2 = "{}"'.format(KEY2)
    res = dbtools.query(db, sql)

    # 生成字典
    setting_collection = {}
    for row in res.rows:
        setting_collection[row['key1']] = row['value']

    tmpl = '/backend/setting.html'
    if 1 == request.args.get('setting', type=int):
        tmpl = '/backend/setting1.html'
    elif 2 == request.args.get('setting', type=int):
        tmpl = '/backend/setting2.html'
    return render_template(tmpl, setting_collection=setting_collection)


@app.route('/backend/manager_org/<id>')
@login_required
def backend_manager_org(id):
    ''' 管理员负责单位'''
    sql = SQL_MANAGER_INFO.format(' and U.id = {} '.format(id), '')
    manager_info = dbtools.query_one(db, sql)
    return render_template('/backend/manager_org.html', manager_info=manager_info)


@app.route('/backend/manager_org_set/<manager_id>/<org_id>')
@login_required
def backend_manager_org_set(manager_id, org_id):
    '''管理员负责单位设定
        @todo 用事务管理，若有问题rollback
    '''
    try:
        # 清空该管理员的旧单位相关
        sql = 'select id from o_organization where manager_id={}'.format(manager_id)
        oldorg = dbtools.query_one(db, sql)
        if oldorg:
            sql = 'update o_organization set manager_id=null where id="{}"'.format(oldorg.id)
            dbtools.update(db, sql)#, commit=False)
            sql = 'delete from o_batch_manager_org where manager_id={}'.format(manager_id)
            dbtools.delete(db, sql)#, commit=False)


        sql = 'update o_organization set manager_id={} where id={}'.format(manager_id, org_id)
        dbtools.update(db, sql)#, commit=False)

        update_org_manager(db, org_id)

        sql = 'select * from o_organization where id={}'.format(org_id)
        org = dbtools.query_one(db, sql)
        return org.name
    except Exception, e:
        db.session.rollback()
        return 'ERR'


@app.route('/backend/generate_qrcode')
@login_required
def backend_generate_qrcode():
    '''生成唯一标记二维码并记录'''
    if request.args.get('generate'):
        sql = 'select * from o_qr_code where status is null and user_id={}'.format(current_user.id)
        res = False #dbtools.query_one(db, sql)
        if res:
            code = res['uuid']
        else:
            code = uuid.uuid1()
            sql = 'insert into o_qr_code (uuid, user_id, createtime) values ("{}", {}, now())'.format(code, current_user.id)
            dbtools.insert(db, sql)

        qr = qrcode.QRCode(version=1,error_correction=qrcode.constants.ERROR_CORRECT_L,box_size=200,border=1)
        qr.add_data(code)
        qr.make(fit=True)
        img = qr.make_image()
        return server_pil_image(img)

    return render_template('/backend/generate_qrcode.html')


''' 工单报警定时任务间隔时间；缺省30分钟 '''
try:
    BACKEND_TASK_PROCESS_INTERVAL = int(dbtools.load_setting(db, 'task_alert_interval', 'BACKEND')) or (30 * 60)
except:
    BACKEND_TASK_PROCESS_INTERVAL = (30 * 60)


def backend_timer_process():
    '''定时任务，用来处理工单报警等事务
     https://www.cnblogs.com/leiziv5/p/7886564.html   '''

    print '工单报警处理 : TODO 发送微信通知到预定装维人员 ...'

    # 继续下一次
    scheduler.add_job(func=backend_timer_process, id='1', args=(), trigger='interval', seconds=BACKEND_TASK_PROCESS_INTERVAL, replace_existing=True)
