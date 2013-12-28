#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2

class HomePage(webapp2.RequestHandler):
    """docstring for HomePage"""
    Problems = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pratices of CS253 on Udacity</title>
      <style type="text/css">
        body {
            background-color: #F3F3F4;
        }
        span {
            font-family: Sans-serif;
            font-size: 17px;
            color : gray;
            position:relative;
            top:0px;
            right:3px;
        }
        input[type=submit] {
            position:relative;
            top:0px;
            left:0px;
            font-size: 20px
        }
        .links-title {
            position:absolute;
            top:110px;
            right: 60px;
            font-family:Sans-serif;
        }
        .links {
            position: relative;
            left: 40px
        }
      </style>
    </head>
    <body>
        <h1 style = "text-align:center;">Porjects for CS253 on Udacity</h1>
        <h4 style = "text-align:center;">Done by Honghao Zhang</h4>
        <table border="0">
        <tr>
            <td>
                <form action="/p1-1">
                <input type="submit" value="Prob1-1: Hello, Udacity!">
                </form>
            </td>
            <td><span>&nbsp; Output: Simply Show "Hello, Udacity!"</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p2-1">
                <input type="submit" value="Prob2-1: Rot13">
                </form>
            </td>
            <td><span>&nbsp; Get&Post: Encrypt using ROT13</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p2-2">
                <input type="submit" value="Prob2-2: User Signup">
                </form>
            </td>
            <td><span>&nbsp; Get&Post: A simple user register page</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p3-0">
                <input type="submit" value="Prob3-0: ASCII Arts">
                </form>
            </td>
            <td><span>&nbsp; Database: An ASCII Arts archive website</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p3-1">
                <input type="submit" value="Prob3-1: Basic Blog">
                </form>
            </td>
            <td><span>&nbsp; Database: A Simple Blog</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p4-0">
                <input type="submit" value="Prob4-0: Visits Count">
                </form>
            </td>
            <td><span>&nbsp; Cookies: Visited times</span></td>
        </tr>

        <tr>
            <td><span style = "font-size:14px; color: black;">&nbsp;&nbsp; Prob4: User Account: </span></td>
            <td>
                <form action="/p4/welcome" style = "position:relative; left:5px;">
                <input type="submit" value="Prob4: Welcome">
                </form>
            </td>
            <td><span style = "position:relative; left:-197px;">&nbsp; Cookies: User Account Welcome Page</span></td>
        </tr>

        <tr>
            <td></td>
            <td>
                <form action="/p4/signup" style = "position:relative; left:5px;">
                <input type="submit" value="Prob4-1: Signup">
                </form>
            </td>
            <td><span style = "position:relative; left:-197px;">&nbsp; Cookies: Signup an account</span></td>
        </tr>

        <tr>
            <td></td>
            <td>
                <form action="/p4/login" style = "position:relative; left:5px;">
                <input type="submit" value="Prob4-2: Login">
                </form>
            </td>
            <td><span style = "position:relative; left:-197px;">&nbsp; Cookies: Login an existed account</span></td>
        </tr>
        <tr>
            <td></td>
            <td>
                <form action="/p4/logout" style = "position:relative; left:5px;">
                <input type="submit" value="Prob4-3: Logout">
                </form>
            </td>
            <td><span style = "position:relative; left:-197px;">&nbsp; Cookies: Logout current account</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p5-0">
                <input type="submit" value="Prob5-0: Geolocation">
                </form>
            </td>
            <td><span>&nbsp; Http Client: ASCII Arts with Geolocation</span></td>
        </tr>

        <tr>
            <td>
                <form action="/p5-1">
                <input type="submit" value="Prob5&6: Blog with json">
                </form>
            </td>
            <td><span>&nbsp; Json: A simple Blog with json</span></td>
        </tr>
        <tr>
            <td></td>
            <td><span style = "font-size: 13px; color: grey; position:relative; left:3px; top:-3px;">&nbsp; *try to add '/.json' after pages</span></td>
        </tr>

        <tr>
            <td>
                <form action="/final">
                <input type="submit" value="Final: Wiki Page">
                </form>
            </td>
            <td><span>&nbsp; A website can be eddited</span></td>
        </tr>

        <table class= "links-title">
            <tr>
                <td style = "font-size:17px; font-weight: bold;">Other Projects:</td>
            </tr>
            <tr>
                <td class= "links"><a href="http://udacity-cs253.appspot.com/blog" target="_blank">http://udacity-cs253.appspot.com/blog</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://cookie.mypathforpython.appspot.com/blog/" target="_blank">http://cookie.mypathforpython.appspot.com/blog/</a></td>
            </tr>

            <tr>
                <td class= "links"><a href="http://vl-hw3.appspot.com/blog/" target="_blank">http://vl-hw3.appspot.com/blog/</a></td>
            </tr>
            

            <tr>
                <td class= "links"><a href="http://t-dispatcher-360.appspot.com/blog/" target="_blank">http://t-dispatcher-360.appspot.com/blog/</a></td>
            </tr>
            
            <tr>
                <td class= "links"><a href="http://emergingcode.appspot.com/blog" target="_blank">http://emergingcode.appspot.com/blog</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://cs253-homework-sean.appspot.com/blog" target="_blank">http://cs253-homework-sean.appspot.com/blog</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://cs253-jballesteros.appspot.com/blog" target="_blank">http://cs253-jballesteros.appspot.com/blog</a></td>
            </tr>

            <tr>
                <td><br></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://mh-udacity-cs253.appspot.com/" target="_blank">http://mh-udacity-cs253.appspot.com/</a></td>
            </tr>
            
            <tr><td><br></td></tr>
            <tr>
                <td style = "font-size:17px; font-weight: bold;">Useful Websites:</td>
            </tr>
            <tr>
                <td class= "links"><a href="https://www.udacity.com/course/cs253" target="_blank">CS253: "Web Development" HomePage</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://udaciousprojects.appspot.com" target="_blank">Udacious Projects</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://friendacity.appspot.com/" target="_blank">Friendacity</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="http://www.foragoodstrftime.com" target="_blank">strftime() easy formatting</a></td>
            </tr>
            <tr>
                <td class= "links"><a href="https://pythex.org" target="_blank">Python regular expression editor</a></td>
            </tr>

            
        </table>
    </body>
    </html>
        """
    def get(self):
        self.response.out.write(self.Problems)

#####################################################################################################
class Prob1_1(webapp2.RequestHandler):
    """docstring for Prob2sec1"""
    def write(self):
        self.response.out.write("Hello, Udacity!")
    
    def get(self):
        self.write()

#####################################################################################################
class Prob2_1(webapp2.RequestHandler):
    """docstring for Prob2sec1"""
    text = """
        <form method="post">
        <h2>Enter some text to ROT13:</h2>
        <textarea name="text" rows="4" cols="40">%(textInput)s</textarea>
        <br>
        <input type = "submit" value="Encode/Decode">
        </form>
        """
    def write(self, textInput = ""):
        self.response.out.write(self.text % {"textInput" : textInput})
    
    def get(self):
        self.write()
    def rot13(self, textToEncode):
        result = ""
        for letter in textToEncode:
            if 'a' <= letter <= 'z':
                result += chr((ord(letter) + 13 - ord('a')) % 26 + ord('a'))
            elif 'A' <= letter <= 'Z':
                result += chr((ord(letter) + 13 - ord('A')) % 26 + ord('A'))
            else:
                if letter == '"':
                    result += '&quot'
                elif letter == '>':
                    result += '&gt'
                elif letter == '<':
                    result += '&lt'
                elif letter == '&':
                    result += '&amp'
                else:
                    result += letter
        return result
    def post(self):
        textInput = self.request.get('text')
        result = self.rot13(textInput)
        self.response.out.write(self.text % {"textInput" : result})

#####################################################################################################
import re
class Prob2_2(webapp2.RequestHandler):
    """docstring for Prob2_2"""
    signup_page = """
    <!DOCTYPE html>

    <html>
      <head>
        <title>Sign Up</title>
        <style type="text/css">
          .label {text-align: right}
          .error {color: red}
        </style>

      </head>

      <body>
        <h2>Signup</h2>
        <form method="post">
          <table>
            <tr>
              <td class="label">Username</td>
              <td>
                <input type="text" name="username" value="%(username)s">
              </td>
              <td class="error">%(username_error)s</td>
            </tr>

            <tr>
              <td class="label">Password</td>
              <td>
                <input type="password" name="password" value="%(password)s">
              </td>
              <td class="error">%(password_error)s</td>
            </tr>

            <tr>
              <td class="label">Verify Password</td>
              <td>
                <input type="password" name="verify" value="%(verify)s">
              </td>
              <td class="error">%(verify_error)s</td>
            </tr>

            <tr>
              <td class="label">Email (optional)</td>
              <td>
                <input type="text" name="email" value="%(email)s">
              </td>
              <td class="error">%(email_error)s</td>
            </tr>
          </table>

          <input type="submit" value="Register!">
        </form>
      </body>

    </html>
    """
    username = ""
    username_error = ""
    password = ""
    password_error = ""
    verify = ""
    verify_error = ""
    email = ""
    email_error = ""

    def write(self, username = "", username_error = "", 
                    password = "", password_error = "",
                    verify = "", verify_error = "",
                    email = "", email_error = ""):
        self.response.write(self.signup_page %{"username" : username, "username_error" : username_error,
                                   "password" : password, "password_error" : password_error,
                                   "verify" : verify, "verify_error" : verify_error,
                                   "email" : email, "email_error" : email_error})

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_username(self, username):
        return self.USER_RE.match(username)
    def valid_password(self, password):
        return self.PASSWORD_RE.match(password)
    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
        
    def valid_verify(self, password, verify):
        return password == verify 

    def get(self):
        self.username = ""
        self.username_error = ""
        self.password = ""
        self.password_error = ""
        self.verify = ""
        self.verify_error = ""
        self.email = ""
        self.email_error = ""
        self.write()
    def updateErrorMessages(self):
        self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
        self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
        self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
        self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
        if not (self.username_error == "" and self.password_error == ""
                and self.verify_error == "" and self.email_error == ""):
            self.password = ""
            self.verify = ""

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.updateErrorMessages()
        if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
            #self.write_successful(self.username)
            self.redirect('/p2-2/welcome?username=%s' % self.username)
            # self.redirect('/p2-2/welcome')
        else:
            self.write(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)

class Prob2_2_welcome(webapp2.RequestHandler):
    """docstring for Prob2_2_welcome"""
    signup_successful = """
    <!DOCTYPE html>

    <html>
      <head>
        <title>Unit 2 Signup</title>
      </head>

      <body>
        <h2>Welcome, %(username)s!</h2>
      </body>
    </html>
    """
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    def valid_username(self, username):
        return self.USER_RE.match(username)
    def get(self):
        username = self.request.get("username")
        if not self.valid_username(username):
            self.redirect('/p2-2')
        else:
            self.response.write(self.signup_successful %{"username" : username})

#####################################################################################################
import os
import jinja2
from google.appengine.ext import db
import time
template_dir = os.path.join(os.path.dirname(__file__), 'cs253')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# global functions can be called in jinja2 templates
def replace_endl(content):
    return content.replace('\n', '<br>')
jinja_env.globals.update(replace_endl=replace_endl)
def localTime():
    return time.localtime()
jinja_env.globals.update(localTime=localTime)


import logging
CACHE = {}
def top_arts(update = False):
    key = 'top'
    if not update and key in CACHE:
        arts = CACHE[key]
    else:
        logging.error("DB query")
        # arts = db.GqlQuery('SELECT *'
        #                    'FROM Art'
        #                    'ORDER BY created DESC'
        #                    'LIMIT 10')
        arts = db.GqlQuery('SELECT * FROM Art ORDER BY created DESC')
        arts = list(arts)
        CACHE[key] = arts
    return arts

class Handle(webapp2.RequestHandler):
    """docstring for Handle"""
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        #self.response.write(self.render_str(template, **kw))

class Art(db.Model):
    """docstring for Art"""
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Prob3_0(Handle):
    """docstring for Prob3_0"""
    def render_page(self, title = "", art = "", error = ""):
        #arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
        arts = top_arts()
        self.render("/unit3/ascii_art.html", title = title, art = art, error = error, arts = arts)
    def get(self):
        self.render_page() #rander page using render_page
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(title = title, art = art)
            a.put()
            #sleep for 0.1 second to wait db to update
            time.sleep(0.1)
            #rerun the query and update the cache
            top_arts(True)
            self.redirect("/p3-0")
        else:
            error = "We need both a title and some artwork!"
            self.render_page(title, art, error)

#####################################################################################################
class Blog(db.Model):
    """docstring for Art"""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    posted = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Prob3_1(Handle):
    """docstring for ClassName"""
    def render_page(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY posted DESC")
        self.render("/unit3/blog_frontpage.html", blogs = blogs)
    def get(self):
        self.render_page()
class Prob3_1_newpost(Handle):
    """docstring for Prob3_1_newpost"""
    def render_page(self, subject = "", content = "", error = ""):
        self.render("/unit3/blog_newpost.html", subject = subject, content = content, error = error)
    def get(self):
        self.render_page()
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            b = Blog(subject = subject, content = content)
            b_key = b.put() # Key('Blog', id)
            self.response.write("Post Successfully!")
            time.sleep(0.5) #sleep for 0.1 second to wait db to update
            self.redirect("/p3-1/%d" % b_key.id())
        else:
            error = "We need both a subject and some content!"
            self.render_page(subject, content, error)
class Prob3_1_permalink(Handle):
    """docstring for ClassName"""
    def render_page(self):
        self.render("/unit3/blog_frontpage.html", blogs = blogs)
    def get(self, blog_id):
        s = Blog.get_by_id(int(blog_id))
        if s:
            self.render("/unit3/blog_frontpage.html", blogs = [s])
        else:
            self.response.write("No Blog")


#####################################################################################################
#import hashlib
import hmac
class Prob4_0(webapp2.RequestHandler):
    """docstring for ClassName"""
    SECRET = "imasecret"
    def hash_str(self, s):
        #return hashlib.md5(s).hexdigest()
        return hmac.new(self.SECRET, s).hexdigest()

    def make_secure_val(self, s):
        return "%s|%s" % (s, self.hash_str(s))

    def check_secure_val(self, h):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        visits = 0

        visits_cookie_str = self.request.cookies.get('visits')
        if visits_cookie_str:
            cookies_val = self.check_secure_val(visits_cookie_str)
            if cookies_val:
                visits = int(cookies_val)

        clear = self.request.get("isclear")
        if clear:
            visits = -1
            self.redirect("/p4-0")
        visits += 1

        new_cookie_val = self.make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        if visits >= 10:
            self.response.out.write("Aha, you did it! This page is just used for practice.<br>")
            self.response.out.write("Clear Cookies to restart again.")
            clear = """
                <form method="get">
                    <input name="isclear" type="submit" value="Clear Cookies">
                </form>
                """
            self.response.out.write(clear)
        else:
            self.response.out.write("You've been here %s times!" % visits)
            self.response.out.write("<br>")
            self.response.out.write("Try to refresh this page until 10 times...")
            clear = """
                <form method="get">
                    <input name="isclear" type="submit" value="Clear Cookies">
                </form>
                """
            self.response.out.write(clear)

#####################################################################################################
import random
import string
import hashlib

## used for make hash string in cookies
SECRET = "random_strings"
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class BlogHandle(webapp2.RequestHandler):
    """docstring for Handle"""
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        #params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val == None:
            return None
        else:
            return check_secure_val(cookie_val)
        #return cookie_val and check_secure_val(cookie_val)

    ## login means set the cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    ## logout means clear the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

## used for storing password in database
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    return h ==  make_pw_hash(name, pw, salt)

class User(db.Model):
    """User DataBase"""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    register_time = db.DateTimeProperty(auto_now = True)
        
class Prob4_signup(BlogHandle):
    """docstring for ClassName"""
    username = ""
    username_error = ""
    password = ""
    password_error = ""
    verify = ""
    verify_error = ""
    email = ""
    email_error = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = "",
                    verify = "", verify_error = "",
                    email = "", email_error = ""):
        self.render("/unit4/signup.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error,
                    verify = verify, verify_error = verify_error,
                    email = email, email_error = email_error)

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_username(self, username):
        return self.USER_RE.match(username)
    def valid_password(self, password):
        return self.PASSWORD_RE.match(password)
    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
        
    def valid_verify(self, password, verify):
        return password == verify

    def updateErrorMessages(self):
        self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
        self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
        self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
        self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
        if not (self.username_error == "" and self.password_error == ""
                and self.verify_error == "" and self.email_error == ""):
            self.password = ""
            self.verify = "" 

    def get(self):
        self.username = ""
        self.username_error = ""
        self.password = ""
        self.password_error = ""
        self.verify = ""
        self.verify_error = ""
        self.email = ""
        self.email_error = ""
        self.render_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.updateErrorMessages()
        if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
            users = db.GqlQuery("SELECT * FROM User")
            # alreadyExist = False
            # for user in users:
            #     if self.username == user.name:
            #         alreadyExist = True
            userList = []
            for user in users:
                userList.append(user.name)
            alreadyExist = self.username in userList
            if not alreadyExist:
                newuser = User(name = self.username,
                               pw_hash = make_pw_hash(self.username, self.password),
                               email = self.email)
                newuser.put()
                self.login(newuser)
                time.sleep(0.1)
                self.redirect("/p4/welcome")
            else:
                self.username_error = "'%s' already exists." % self.username
                self.password = ""
                self.verify = ""
                self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
        else:
            self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
class Prob4_welcome(BlogHandle):
    """docstring for Prob4_1_welcome"""
    signup_successful = """
    <!DOCTYPE html>

    <html>
      <head>
        <title>Unit 2 Signup</title>
      </head>

      <body>
        <h2>Welcome, %(username)s!</h2>
      </body>
    </html>
    """
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if uid == None:
            self.response.write("<h2>You haven't logged in yet...</h2>")
        else: 
            user = User.get_by_id(int(uid))
            self.response.write(self.signup_successful % {"username" : user.name})

class Prob4_login(BlogHandle):
    """docstring for Prob4_1_welcome"""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = ""):
        self.render("/unit4/login.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error)
    def get(self):
        self.render_page()
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        
        exsitUser = db.GqlQuery("SELECT * FROM User WHERE name= :name_to_query", name_to_query = self.username)
        if exsitUser.get() != None:
            if valid_pw(self.username, self.password, exsitUser[0].pw_hash):
                self.login(exsitUser[0])
                self.redirect("/p4/welcome")
            else:
                self.password_error = "Password is invalid!"
                self.render_page(self.username, "", "", self.password_error)
        else:
            self.username_error = "'%s' doesn't exist" % self.username
            self.render_page("", self.username_error, "", "")
            
class Prob4_logout(BlogHandle):
    """docstring for Prob4_logout"""
    def get(self):
        # uid = self.read_secure_cookie('user_id')
        # user = User.get_by_id(int(uid))
        self.logout()
        #self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' %nullString)
        # self.render("/unit4/message.html", message = "'%s' logout successfully" % user.name)
        # time.sleep(2)
        self.redirect('/p4/signup')

#####################################################################################################
import urllib2
from xml.dom import minidom

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return
    if content:
        #parse the xml and find the coordinates
        d = minidom.parseString(content)
        coords = d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon, lat = coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat, lon)

CACHE = {}
def top_arts(update = False):
    key = 'top'
    if not update and key in CACHE:
        arts = CACHE[key]
    else:
        logging.error("DB query")
        # arts = db.GqlQuery('SELECT *'
        #                    'FROM Art'
        #                    'ORDER BY created DESC'
        #                    'LIMIT 10')
        arts = db.GqlQuery('SELECT * FROM Art_new ORDER BY created DESC')
        arts = list(arts)
        CACHE[key] = arts
    return arts

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    # marker = "markers=%s"
    # result = ""
    # for p in points:
    #     coords = str(p.lat) + ',' + str(p.lon)
    #     result += marker % coords + "&"
    # result = result[:-1]
    # return GMAPS_URL + result
    markers = '&'.join('markers=%s,%s' % (p.lat, p.lon)
                        for p in points)
    return GMAPS_URL + markers

class Art_new(db.Model):
    """docstring for Art"""
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty() # consider the old database

class Prob5_0(Handle):
    """docstring for Prob5_0"""
    def render_page(self, title = "", art = "", error = ""):
        #arts = db.GqlQuery("SELECT * FROM Art_new ORDER BY created DESC")
        #prevent the running of multiple queries
        #arts = list(arts)
        arts = top_arts()

        # find which arts have coords
        points = filter(None, (a.coords for a in arts))
        
        # if we have any arts coords, make an image url
        # display the image url
        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("/unit5/ascii_art.html", title = title, art = art, 
                    error = error, arts = arts, img_url = img_url)
    def get(self):
        # self.write(self.request.remote_addr)
        # self.write(repr(get_coords(self.request.remote_addr)))
        self.render_page() #rander page using render_page
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art_new(title = title, art = art)
            coords = get_coords(self.request.remote_addr)
            # if we have coordinates, add them to the Art_new
            if coords:
                a.coords = coords
            a.put()
            #sleep for 0.1 second to wait db to update
            time.sleep(0.1)
            #rerun the query and update the cache
            top_arts(True)
            self.redirect("/p5-0")
        else:
            error = "We need both a title and some artwork!"
            self.render_page(title, art, error)

#####################################################################################################
from google.appengine.api import memcache
def memcache_blogs(update = False):
    key = 'top'
    blogs = memcache.get(key)
    if blogs is None or update:
        logging.error('DB QUERY')
        blogs = db.GqlQuery('SELECT * FROM Blog ORDER BY posted DESC')
        blogs = list(blogs)
        memcache.set(key, blogs)
        memcache.set('query_time', time.time())
    elif memcache.get('query_time') == None:
        memcache.set('query_time', time.time())
    return blogs
def memcache_queryTime(key):
    lastQueryTime = memcache.get(key)
    if lastQueryTime:
        elapsedTime = time.time() - float(lastQueryTime)
        return str(round(elapsedTime)).split('.')[0]
    else:
        return None
class Prob5_1(BlogHandle):
    """docstring for ClassName"""
    def render_page(self):
        # blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY posted DESC")
        uid = self.read_secure_cookie('user_id')
        blogs = memcache_blogs()
        queried_time = "Queried %s seconds ago" % memcache_queryTime('query_time')
        if uid == None:
            self.render("/unit5/blog_frontpage.html", blogs = blogs, uid = '', queried_time = queried_time)
        else:
            user = User.get_by_id(int(uid))
            if user == None:
                self.render("/unit5/blog_frontpage.html", blogs = blogs, uid = '', queried_time = queried_time)
            else:
                self.render("/unit5/blog_frontpage.html", blogs = blogs, uid = user.name, queried_time = queried_time)
    def get(self):
        self.render_page()

class Prob5_1_newpost(BlogHandle):
    """docstring for Prob5_1_newpost"""
    def render_page(self, subject = "", content = "", error = ""):
        self.render("/unit5/blog_newpost.html", subject = subject, content = content, error = error)
    def get(self):
        self.render_page()
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            b = Blog(subject = subject, content = content)
            b_key = b.put() # Key('Blog', id)
            self.response.write("Post Successfully!")
            time.sleep(0.5) #sleep for 0.1 second to wait db to update
            #rerun the query and update the cache
            memcache_blogs(True)
            self.redirect("/p5-1/%d" % b_key.id())
        else:
            error = "We need both a subject and some content!"
            self.render_page(subject, content, error)
def memcache_permalink(blog_id):
    id = int(blog_id)
    blog_per = memcache.get(str(id))
    if blog_per is None:
        blog_per = Blog.get_by_id(id)
        memcache.set(str(id), blog_per)
        memcache.set('query_permalink' + str(id), time.time())
    elif memcache.get('query_permalink' + str(id)) == None:
        memcache.set('query_permalink' + str(id), time.time())
    return blog_per
class Prob5_1_permalink(BlogHandle):
    """docstring for ClassName"""
    def render_page(self, blog_id):
        blog = memcache_permalink(blog_id)
        queried_time = "Queried %s seconds ago" % memcache_queryTime('query_permalink' + str(int(blog_id)))
        if blog:
            uid = self.read_secure_cookie('user_id')
            return_url = '<a href = "/p5-1" class = "return">< Return</a>'
            if uid == None:
                self.render("/unit5/blog_frontpage.html", blogs = [blog], uid = '', queried_time = queried_time)
            else:
                user = User.get_by_id(int(uid))
                self.render("/unit5/blog_frontpage.html", blogs = [blog], uid = user.name, return_url = return_url, queried_time = queried_time)
        else:
            self.redirect('/p5-1')
    def get(self, blog_id):
        self.render_page(blog_id)

import json
import copy

class Prob5_1_Json(BlogHandle):
    """docstring for ClassName"""
    def render_page(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY posted DESC")
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"

        json_output = {}
        json_output_list = []
        for blog in blogs:
            json_output.clear()

            json_output['content'] = blog.content
            json_output['created'] = blog.posted.strftime("%b %d, %Y")
            json_output['last_modified'] = blog.last_modified.strftime("%b %d, %Y")
            json_output['subject'] = blog.subject

            ele = copy.copy(json_output)
            json_output_list.append(ele)
        json_output_list = json.dumps(json_output_list)
        self.write(json_output_list)
    def get(self):
        self.render_page()

class Prob5_1_permalink_Json(BlogHandle):
    """docstring for ClassName"""
    def get(self, blog_id):
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        blog = Blog.get_by_id(int(blog_id))
        if blog:
            json_output = {}
            json_output['content'] = blog.content
            json_output['created'] = blog.posted.strftime("%b %d, %Y")
            json_output['last_modified'] = blog.last_modified.strftime("%b %d, %Y")
            json_output['subject'] = blog.subject

            self.write(json.dumps(json_output))
            
        else:
            self.redirect('/p5-1')
            # self.error(404)
            # return
            #self.response.write("No Blog")

class Prob5_1_signup(BlogHandle):
    """docstring for ClassName"""
    username = ""
    username_error = ""
    password = ""
    password_error = ""
    verify = ""
    verify_error = ""
    email = ""
    email_error = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = "",
                    verify = "", verify_error = "",
                    email = "", email_error = ""):
        self.render("/unit5/signup.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error,
                    verify = verify, verify_error = verify_error,
                    email = email, email_error = email_error)

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_username(self, username):
        return self.USER_RE.match(username)
    def valid_password(self, password):
        return self.PASSWORD_RE.match(password)
    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
        
    def valid_verify(self, password, verify):
        return password == verify

    def updateErrorMessages(self):
        self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
        self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
        self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
        self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
        if not (self.username_error == "" and self.password_error == ""
                and self.verify_error == "" and self.email_error == ""):
            self.password = ""
            self.verify = "" 

    def get(self):
        self.username = ""
        self.username_error = ""
        self.password = ""
        self.password_error = ""
        self.verify = ""
        self.verify_error = ""
        self.email = ""
        self.email_error = ""
        self.render_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.updateErrorMessages()
        if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
            users = db.GqlQuery("SELECT * FROM User")
            # alreadyExist = False
            # for user in users:
            #     if self.username == user.name:
            #         alreadyExist = True
            userList = []
            for user in users:
                userList.append(user.name)
            alreadyExist = self.username in userList
            if not alreadyExist:
                newuser = User(name = self.username,
                               pw_hash = make_pw_hash(self.username, self.password),
                               email = self.email)
                newuser.put()
                self.login(newuser)
                time.sleep(0.01)
                self.redirect("/p5-1/welcome")
            else:
                self.username_error = "'%s' already exists." % self.username
                self.password = ""
                self.verify = ""
                self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
        else:
            self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
class Prob5_1_welcome(BlogHandle):
    """docstring for Prob5_1_welcome"""
    signup_successful = """
    <!DOCTYPE html>

    <html>
      <head>
        <title>Signup</title>
      </head>

      <body>
        <h2>Welcome, %(username)s!</h2>
      </body>
    </html>
    """
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if uid == "":
            #self.response.write("<h2>You haven't logged in yet...</h2>")
            #time.sleep(1)
            self.redirect("/p5-1")
        else: 
            user = User.get_by_id(int(uid))
            #self.response.write(self.signup_successful % {"username" : user.name})
            #time.sleep(1)
            self.redirect("/p5-1")

class Prob5_1_login(BlogHandle):
    """docstring for Prob5_1_login"""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = ""):
        self.render("/unit5/login.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error)
    def get(self):
        self.render_page()
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        
        exsitUser = db.GqlQuery("SELECT * FROM User WHERE name= :name_to_query", name_to_query = self.username)
        if exsitUser.get() != None:
            if valid_pw(self.username, self.password, exsitUser[0].pw_hash):
                self.login(exsitUser[0])
                self.redirect("/p5-1/welcome")
            else:
                self.password_error = "Password is invalid!"
                self.render_page(self.username, "", "", self.password_error)
        else:
            self.username_error = "'%s' doesn't exist" % self.username
            self.render_page("", self.username_error, "", "")
            
class Prob5_1_logout(BlogHandle):
    """docstring for Prob5_1_logout"""
    def get(self):
        self.logout()
        ref = self.request.headers['Referer']
        self.redirect(ref)

class Prob5_1_flush(BlogHandle):
    def get(self):
        memcache.flush_all()
        self.redirect('/p5-1')
#####################################################################################################
#new project!
# class Wiki(db.Model):
#     """docstring for Art"""
#     content = db.TextProperty(required = True)
#     #author = db.ReferenceProperty(required = True)
#     created = db.DateTimeProperty(auto_now_add = True)
#     last_modified = db.DateTimeProperty(auto_now = True)

# class WikiHandle(webapp2.RequestHandler):
#     def write(self, *a, **kw):
#         self.response.write(*a, **kw)
#     def render_str(self, template, **params):
#         #params['user'] = self.user
#         t = jinja_env.get_template(template)
#         return t.render(params)
#     def render(self, template, **kw):
#         self.write(self.render_str(template, **kw))

#     def set_secure_cookie(self, name, val):
#         cookie_val = make_secure_val(val)
#         self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

#     def read_secure_cookie(self, name):
#         cookie_val = self.request.cookies.get(name)
#         if cookie_val == None:
#             return None
#         else:
#             return check_secure_val(cookie_val)

#     ## login means set the cookie
#     def login(self, user):
#         self.set_secure_cookie('user_id', str(user.key().id()))

#     ## logout means clear the cookie
#     def logout(self):
#         self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# class Final_signup(WikiHandle):
#     username = ""
#     username_error = ""
#     password = ""
#     password_error = ""
#     verify = ""
#     verify_error = ""
#     email = ""
#     email_error = ""
#     referer = ""
#     def render_page(self, username = "", username_error = "", 
#                     password = "", password_error = "",
#                     verify = "", verify_error = "",
#                     email = "", email_error = "",
#                     referer = ""):
#         self.render("/final/signup.html", username = username, username_error = username_error, 
#                     password = password, password_error = password_error,
#                     verify = verify, verify_error = verify_error,
#                     email = email, email_error = email_error,
#                     referer = self.request.referer)

#     USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
#     PASSWORD_RE = re.compile(r"^.{3,20}$")
#     EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
#     def valid_username(self, username):
#         return self.USER_RE.match(username)
#     def valid_password(self, password):
#         return self.PASSWORD_RE.match(password)
#     def valid_email(self, email):
#         return self.EMAIL_RE.match(email)
        
#     def valid_verify(self, password, verify):
#         return password == verify

#     def updateErrorMessages(self):
#         self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
#         self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
#         self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
#         self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
#         if not (self.username_error == "" and self.password_error == ""
#                 and self.verify_error == "" and self.email_error == ""):
#             self.password = ""
#             self.verify = "" 

#     def get(self):
#         self.username = ""
#         self.username_error = ""
#         self.password = ""
#         self.password_error = ""
#         self.verify = ""
#         self.verify_error = ""
#         self.email = ""
#         self.email_error = ""
#         self.referer = ""
#         self.render_page()

#     def post(self):
#         self.username = self.request.get('username')
#         self.password = self.request.get('password')
#         self.verify = self.request.get('verify')
#         self.email = self.request.get('email')
#         self.referer = self.request.get('referer')
#         self.updateErrorMessages()
#         if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
#             users = db.GqlQuery("SELECT * FROM User")
#             userList = []
#             for user in users:
#                 userList.append(user.name)
#             alreadyExist = self.username in userList
#             if not alreadyExist:
#                 newuser = User(name = self.username,
#                                pw_hash = make_pw_hash(self.username, self.password),
#                                email = self.email)
#                 newuser.put()
#                 self.login(newuser)
#                 time.sleep(0.01)
#                 #self.redirect("/final/welcome")
#                 self.redirect(str(self.referer))
#             else:
#                 self.username_error = "'%s' already exists." % self.username
#                 self.password = ""
#                 self.verify = ""
#                 self.render_page(self.username, self.username_error,
#                        self.password, self.password_error,
#                        self.verify, self.verify_error,
#                        self.email, self.email_error)
#         else:
#             self.render_page(self.username, self.username_error,
#                        self.password, self.password_error,
#                        self.verify, self.verify_error,
#                        self.email, self.email_error)

# class Final_login(WikiHandle):
#     def render_page(self, username = "", username_error = "", 
#                     password = "", password_error = "", referer = ""):
#         self.render("/final/login.html", username = username, username_error = username_error, 
#                     password = password, password_error = password_error, referer = self.request.referer)
#     def get(self):
#         self.render_page()
#     def post(self):
#         self.username = self.request.get('username')
#         self.password = self.request.get('password')
#         self.referer = self.request.get('referer')
        
#         exsitUser = db.GqlQuery("SELECT * FROM User WHERE name= :name_to_query", name_to_query = self.username)
#         if exsitUser.get() != None:
#             if valid_pw(self.username, self.password, exsitUser[0].pw_hash):
#                 self.login(exsitUser[0])
#                 #self.redirect("/final/welcome")
#                 self.redirect(str(self.referer))
#             else:
#                 self.password_error = "Password is invalid!"
#                 self.render_page(self.username, "", "", self.password_error)
#         else:
#             self.username_error = "'%s' doesn't exist" % self.username
#             self.render_page("", self.username_error, "", "")

# class Final_logout(WikiHandle):
#     def get(self):
#         self.logout()
#         #ref = self.request.headers['Referer']
#         self.redirect(self.request.referer)

# class Final_welcome(WikiHandle):
#     signup_successful = """
#     <!DOCTYPE html>

#     <html>
#       <head>
#         <title>Signup</title>
#       </head>

#       <body>
#         <h2>Welcome, %(username)s!</h2>
#       </body>
#     </html>
#     """

#     def get(self):
#         uid = self.read_secure_cookie('user_id')
#         if uid == "":
#             #self.response.write("<h2>You haven't logged in yet...</h2>")
#             #time.sleep(1)
#             self.redirect("/final")
#         else: 
#             user = User.get_by_id(int(uid))
#             #self.response.write(self.signup_successful % {"username" : user.name})
#             #time.sleep(1)
#             self.redirect("/final")

# def set(val, page):
#     memcache.set(val, page)
# def get(val):
#     page = memcache.get(val)
#     if page:
#         return page
#     else:
#         return None

# class Final_frontPage_default(WikiHandle):
#     def get(self):
#         self.redirect('/final/')

# class Final_frontPage_one(WikiHandle):
#     def render_page(self, content, page_id):
#         uid = self.read_secure_cookie('user_id')
#         if uid == None:
#             self.render("/final/content.html", content = content, page_id = page_id, uid = '')
#         else:
#             user = User.get_by_id(int(uid))
#             self.render("/final/content.html", content = content, page_id = page_id, uid = user.name)

#     def get(self, newpage):
#         page_id = newpage.split('/')[1]
#         page = get(page_id)
#         if not page:
#             # set(page_id, "<h1>Welcome to Page: %s</h1> \
#             #               <h3>*You can edit this page by clicking 'Edit' button." % str(page_id))
#             # self.redirect('/final/%s' % str(page_id))
#             if page_id == "":
#                 set(page_id, "<h1>Welcome to Wiki Page</h1> \
#                               <h3>*You can edit this page by clicking 'Edit' button.")
#                 self.redirect('/final/%s' % str(page_id))
#             else:
#                 set(page_id, "")
#                 self.redirect('/final/_edit/%s' % page_id)
#         else:
#             self.render_page(page, page_id)

# class Final_editPage(WikiHandle):
#     def render_page(self, content, page_id):
#         uid = self.read_secure_cookie('user_id')
#         if uid == None:
#             # self.render("/final/edit.html", content = content, page_id = page_id, uid = '')
#             self.redirect('/final/login')
#         else:
#             user = User.get_by_id(int(uid))
#             self.render("/final/edit.html", content = content, page_id = page_id, uid = user.name)

#     def get(self, page):
#         page_id = page.split('/')[1]
#         content = get(page_id)
#         if content == None:
#             self.render_page("", page_id)
#         else: 
#             self.render_page(content, page_id)

#     def post(self, page):
#         page_id = page.split('/')[1]
#         content = self.request.get('content')
#         set(page_id, content)
#         self.redirect('/final/%s' % page_id)

# class Final_fulsh(WikiHandle):
#     def get(self):
#         memcache.flush_all()
#         self.redirect('/final')

# class Final_historyPage(WikiHandle):
#     def get(self, page):
#         pass

class Wiki(db.Model):
    """docstring for Art"""
    content = db.TextProperty(required = False)
    author = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    current_version = db.IntegerProperty(required = True)

class WikiHandle(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        #params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val == None:
            return None
        else:
            return check_secure_val(cookie_val)

    ## login means set the cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    ## logout means clear the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

class Final_signup(WikiHandle):
    username = ""
    username_error = ""
    password = ""
    password_error = ""
    verify = ""
    verify_error = ""
    email = ""
    email_error = ""
    referer = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = "",
                    verify = "", verify_error = "",
                    email = "", email_error = ""):
        self.render("/final/signup.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error,
                    verify = verify, verify_error = verify_error,
                    email = email, email_error = email_error,
                    referer = self.referer)

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_username(self, username):
        return self.USER_RE.match(username)
    def valid_password(self, password):
        return self.PASSWORD_RE.match(password)
    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
        
    def valid_verify(self, password, verify):
        return password == verify

    def updateErrorMessages(self):
        self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
        self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
        self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
        self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
        if not (self.username_error == "" and self.password_error == ""
                and self.verify_error == "" and self.email_error == ""):
            self.password = ""
            self.verify = "" 

    def get(self):
        self.username = ""
        self.username_error = ""
        self.password = ""
        self.password_error = ""
        self.verify = ""
        self.verify_error = ""
        self.email = ""
        self.email_error = ""
        if not self.request.referer == self.request.url:
            self.referer = self.request.referer
        else: self.referer = self.referer
        self.render_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.referer = self.request.get('referer')
        self.updateErrorMessages()
        if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
            users = db.GqlQuery("SELECT * FROM User")
            userList = []
            for user in users:
                userList.append(user.name)
            alreadyExist = self.username in userList
            if not alreadyExist:
                newuser = User(name = self.username,
                               pw_hash = make_pw_hash(self.username, self.password),
                               email = self.email)
                newuser.put()
                self.login(newuser)
                time.sleep(0.01)
                #self.redirect("/final/welcome")
                self.redirect(str(self.referer))
            else:
                self.username_error = "'%s' already exists." % self.username
                self.password = ""
                self.verify = ""
                self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
        else:
            self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)

class Final_login(WikiHandle):
    referer = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = ""):
        self.render("/final/login.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error, referer = self.referer)
    def get(self):
        if not self.request.referer == self.request.url:
            if self.request.referer == None:
                self.referer = self.read_secure_cookie('referer')
            else:
                self.referer = self.request.referer
        else: self.referer = self.referer

        self.render_page()
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.referer = self.request.get('referer')
        
        exsitUser = db.GqlQuery("SELECT * FROM User WHERE name= :name_to_query", name_to_query = self.username)
        if exsitUser.get() != None:
            if valid_pw(self.username, self.password, exsitUser[0].pw_hash):
                self.login(exsitUser[0])
                #self.redirect("/final/welcome")
                self.redirect(str(self.referer))
            else:
                self.password_error = "Password is invalid!"
                self.render_page(self.username, "", "", self.password_error)
        else:
            self.username_error = "'%s' doesn't exist" % self.username
            self.render_page("", self.username_error, "", "")

class Final_logout(WikiHandle):
    def get(self):
        self.logout()
        #ref = self.request.headers['Referer']
        self.redirect(self.request.referer)

class Final_frontPage_default(WikiHandle):
    def get(self):
        self.redirect('/final/')

class Final_frontPage_one(WikiHandle):
    def render_page(self, content, page_id):
        uid = self.read_secure_cookie('user_id')
        if uid == None:
            self.render("/final/content.html", content = content, page_id = page_id, uid = '')
        else:
            user = User.get_by_id(int(uid))
            if user == None:
                self.render("/final/content.html", content = content, page_id = page_id, uid = "")
            else:
                self.render("/final/content.html", content = content, page_id = page_id, uid = user.name)

    def get(self, newpage):
        version = self.request.get('v')

        page_id = newpage.split('/')[1]
        if page_id == "":
            if not version == "":
                page = Wiki.get_by_key_name('.v%s' % version)
            else:
                page = Wiki.get_by_key_name('.')
        else:
            if not version == "":
                page = Wiki.get_by_key_name(page_id + '.v%s' % version)
            else:
                page = Wiki.get_by_key_name(page_id)

        if not page:
            if page_id == "":
                newWiki = Wiki(key_name = '.',
                               content = "<h1>Welcome to Wiki Page</h1> \
                               <h3>*You can edit this page by clicking 'Edit' button.",
                               author = "admin",
                               current_version = 1)
                newWiki.put()
                Wiki(key_name = '.v1',
                               content = "<h1>Welcome to Wiki Page</h1> \
                               <h3>*You can edit this page by clicking 'Edit' button.",
                               author = "admin",
                               current_version = 1).put()
                #time.sleep(0.1)
                self.redirect('/final/%s' % str(page_id))
            else:
                uid = self.read_secure_cookie('user_id')
                self.set_secure_cookie('referer', self.request.url)
                if uid == None:
                    self.redirect('/final/login', permanent=True)
                else:
                    user = User.get_by_id(int(uid))
                    if user == None:
                        self.redirect('/final/login')
                    else:
                        newWiki = Wiki(key_name = page_id, content = "", author = user.name, current_version = 0)
                        newWiki.put()
                        #time.sleep(0.1)
                        self.redirect('/final/_edit/%s' % str(page_id))
        else:
            self.render_page(page.content, page_id)

class Final_editPage(WikiHandle):
    def render_page(self, content, page_id):
        uid = self.read_secure_cookie('user_id')
        if uid == None:
            self.redirect('/final/login')
        else:
            user = User.get_by_id(int(uid))
            if user == None:
                self.redirect('/final/login')
            else:
                self.render("/final/edit.html", content = content, page_id = page_id, uid = user.name)

    def get(self, page):
        page_id = page.split('/')[1]
        if page_id == "":
            page = Wiki.get_by_key_name('.')
        else:
            page = Wiki.get_by_key_name(page_id)

        if page == None:
            self.redirect('/final')
        else:
            self.render_page(page.content, page_id)

    def post(self, page):
        page_id = page.split('/')[1]
        content = self.request.get('content')
        author = self.request.get('author')
        #  front page
        if page_id == "":
            page = Wiki.get_by_key_name('.')
            Wiki(key_name = '.v%s' % str(page.current_version + 1), content = content, author = author, current_version = page.current_version + 1).put()
            Wiki(key_name = '.', content = content, author = author, current_version = page.current_version + 1).put()
        # other page
        else:
            page = Wiki.get_by_key_name(page_id)
            Wiki(key_name = page_id + '.v%s' % str(page.current_version + 1), content = content, author = author, current_version = page.current_version + 1).put()
            Wiki(key_name = page_id, content = content, author = author, current_version = page.current_version + 1).put()
        #time.sleep(0.01)
        self.redirect('/final/%s' % page_id)

class Final_fulsh(WikiHandle):
    def get(self):
        #memcache.flush_all()
        db.delete(db.Query(keys_only=True))
        self.redirect('/final')

class Final_historyPage(WikiHandle):
    def render_page(self, pages, page_id):
        uid = self.read_secure_cookie('user_id')
        if uid == None:
            self.render('/final/history.html', pages = pages, uid = "", page_id = page_id)
        else:
            user = User.get_by_id(int(uid))
            if user == None:
                self.render('/final/history.html', pages = pages, uid = "", page_id = page_id)
            else:
                self.render('/final/history.html', pages = pages, uid = user.name, page_id = page_id)
    def get(self, page):
        page_id = page.split('/')[1]
        if page_id == "":
            parent_page = Wiki.get_by_key_name('.')
            versions = parent_page.current_version
            children_pages = []
            for v in range(versions, 0, -1):
                children_pages.append(Wiki.get_by_key_name('.v%s' % str(v)))
            self.render_page(children_pages, page_id)
        else:
            parent_page = Wiki.get_by_key_name(page_id)
            versions = parent_page.current_version
            children_pages = []
            for v in range(versions, 0, -1):
                children_pages.append(Wiki.get_by_key_name(page_id+ '.v%s' % str(v)))
            self.render_page(children_pages, page_id)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'        
app = webapp2.WSGIApplication([
                               ('/?', HomePage),
                               ('/p1-1/?', Prob1_1),

                               ('/p2-1/?', Prob2_1),
                               ('/p2-2/?', Prob2_2),
                               ('/p2-2/welcome/?', Prob2_2_welcome),
                               ('/p3-0/?', Prob3_0),
                               ('/p3-1/?', Prob3_1),
                               ('/p3-1/newpost/?', Prob3_1_newpost),
                               ('/p3-1/(\d+)/?', Prob3_1_permalink),
                               ('/p4-0/?', Prob4_0),
                               ('/p4/signup/?', Prob4_signup),
                               ('/p4/welcome/?', Prob4_welcome),
                               ('/p4/login/?', Prob4_login),
                               ('/p4/logout/?', Prob4_logout),
                               ('/p5-0/?', Prob5_0),

                               ('/p5-1/?', Prob5_1),
                               ('/p5-1/.json/?', Prob5_1_Json),
                               ('/p5-1/(\d+)/?', Prob5_1_permalink),
                               ('/p5-1/(\d+).json/?', Prob5_1_permalink_Json),
                               ('/p5-1/(\d+)/.json/?', Prob5_1_permalink_Json),
                               ('/p5-1/newpost/?', Prob5_1_newpost),
                               ('/p5-1/signup/?', Prob5_1_signup),
                               ('/p5-1/login/?', Prob5_1_login),
                               ('/p5-1/logout/?', Prob5_1_logout),
                               ('/p5-1/welcome/?', Prob5_1_welcome),
                               ('/p5-1/flush/?', Prob5_1_flush),

                               ('/final', Final_frontPage_default),
                               ('/final/signup', Final_signup),
                               ('/final/login', Final_login),
                               ('/final/logout', Final_logout),
                               ('/final/flush/?', Final_fulsh),
                               ('/final/_edit' + PAGE_RE, Final_editPage),
                               ('/final/_history' + PAGE_RE, Final_historyPage),
                               ('/final' + PAGE_RE, Final_frontPage_one)
                               
                               ], debug=True)
