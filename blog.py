# Copyright 2016 Google Inc.
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

import webapp2
import os
import jinja2
import re
import hashlib
import hmac
import string
import random
import logging

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
SECRET = "somesecret"


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


def render_str(template, **params):

    t = jinja_env.get_template(template)
    return t.render(params)


def blog_key(name="default"):
    return ndb.Key("blogs", name)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return not email or MAIL_RE.match(email)


def make_salt(length=5):
    return "".join(random.choice(string.letters) for x in xrange(0, length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "{}|{}".format(salt, h)


def valid_pw(name, pw, h):
    salt = h.split("|")[0]
    return h == make_pw_hash(name, pw, salt)


def users_key(group="default"):
    return ndb.Key("users", group)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            "Set-Cookie", "{}={}; Path=/".format(name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie("user_id", str(user.key.integer_id()))

    def logout(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie("user_id")
        self.user = uid and User.by_id(int(uid))


class User(ndb.Model):

    """
    This is ndb model to store user.
    """
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        print(type(u))
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Comment(ndb.Model):

    """
    This is ndb model to store comment.
    """
    post_id_comment_belongs = ndb.IntegerProperty(required=True)
    comment_content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    commenter_id = ndb.IntegerProperty(required=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.comment_content.replace("\n", "<br>")
        return render_str("comment.html", c=self)


class Post(ndb.Model):

    """
    This is ndb model to store post.
    """
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    submitter_id = ndb.IntegerProperty(required=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        return render_str("post.html", p=self)


class LikeForPost(ndb.Model):

    """
    This is ndb model to store like for each post.
    """
    number_of_post_liked = ndb.IntegerProperty(required=True)
    post_id_like_belongs = ndb.IntegerProperty(required=True)
    liked_user_id_list = ndb.IntegerProperty(repeated=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)


class LikeToPost(Handler):

    def post(self, post_id):
        posts = Post.query().order(-Post.created)
        posts = posts.fetch(10)

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        like_for_post = LikeForPost.query(post_id_like_belongs == int(uid))

        if user:
            if like_for_post and not(int(uid) in like_for_post.liked_user_id_list):
                like_for_post.number_of_post_liked += 1
                like_for_post.liked_user_id_list.append(int(uid))
                like_for_post.put()
                self.redirect("/blog")

            elif like_for_post and (int(uid) in like_for_post.liked_user_id_list):
                self.redirect("/blog")
            else:
                l = LikeForPost(number_of_post_liked=1,
                                post_id_like_belongs=int(post_id),
                                liked_user_id_list=int(uid))
                l.put()
                self.redirect("blog")
        else:
            self.redirect("blog")

class BlogFront(Handler):

    def get(self):
        posts = Post.query().order(-Post.created)
        posts = posts.fetch(10)

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        like_for_post = LikeForPost().query()
        like_num_post_dict = {}

        for like in like_for_post:
            like_num_post_dict[like.post_id_like_belongs] = like.number_of_post_liked

        if user:
            username = user.name
        else:
            username = ""

        self.render("front.html", username=username, posts=posts, like_num_post_dict=like_num_post_dict)


class PostPage(Handler):

    def get(self, post_id):
        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()
        comments = Comment.query(
            Comment.post_id_comment_belongs == int(post_id))

        if not post:
            self.error(404)
            return

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        if user:
            username = user.name
            self.render(
                "permalink.html", username=username, post=post, comments=comments)
        else:
            self.render("permalink.html", post=post, comments=comments)


class EditPost(Handler):

    def get(self, post_id):
        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        if user:
            username = user.name
            self.render("edit_post.html", username=username, post=post)
        else:
            self.render("edit_post.html", post=post)

    def post(self, post_id):
        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        subject = self.request.get("subject")
        content = self.request.get("content")

        if user and (post.submitter_id == int(uid)):
            post.subject, post.content = subject, content
            post.put()
            self.redirect("/blog/{}".format(str(post.key.integer_id())))
        else:
            self.redirect("/login")


class NewPost(Handler):

    def get(self):
        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        if user:
            username = user.name
            self.render("newpost.html", username=username)
        else:
            self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        if user:
            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, submitter_id=int(uid))
                p.put()
                self.redirect("/blog/{}".format(str(p.key.integer_id())))
            else:
                error = "subject and content please!"
                self.render(
                    "newpost.html", subject=subject, content=content, error=error)
        else:
            error = "Please login to post new..."
            self.redirect("/login")


class NewComment(PostPage):

    def post(self, post_id):
        """
        This method is to handle posting comment in each post page.
        """
        comment_content = self.request.get("comment-content")

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))
        username = user.name

        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        comments_belongs_to_post = Comment.query(
            Comment.post_id_comment_belongs == int(post_id))

        commenter_ids = []
        for comment in comments_belongs_to_post:
            commenter_ids.append(comment.commenter_id)

        if user and (post.submitter_id != int(uid)):
            if comment_content:
                if not (int(uid) in commenter_ids):
                    comment = Comment(post_id_comment_belongs=int(post_id),
                                      comment_content=comment_content,
                                      commenter_id=int(uid))
                    comment.put()
                    self.redirect(
                        "/blog/{}".format(str(post.key.integer_id())))
                else:
                    error = "You can only comment once for each post."
                    self.render(
                        "permalink.html", username=username, post=post, error=error)
            else:
                key = ndb.Key("Post", int(post_id), parent=blog_key())
                post = key.get()
                error = "Please write some comment!"
                self.render(
                    "permalink.html", username=username, post=post, error=error)
        else:
            error = "You can only comment other's comment or need to login to comment."
            self.render(
                "permalink.html", username=username, post=post, error=error)


class DeletePost(Handler):

    def post(self):

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        post_id = self.request.get("post_id")
        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        if user:
            if int(uid) == post.submitter_id:
                key.delete()
                self.redirect("/blog/newpost")
            else:
                error = "You can only delete your post, please understand..."
                self.render("permalink.html", post=post, error=error)
        else:
            error = "Please login to delete your post..."
            self.redirect("/login")


class DeleteComment(DeletePost):

    def post(self, comment_id):

        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))

        post_id = self.request.get("post_id")
        key = ndb.Key("Post", int(post_id), parent=blog_key())
        post = key.get()

        if user:
            if int(uid) == post.submitter_id:
                key.delete()
                self.redirect("/blog/")
            else:
                error = "You can only delete your post, please understand..."
                self.render("permalink.html", post=post, error=error)
        else:
            error = "Please login to delete your post..."
            self.redirect("/login")


class SignUpHandler(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.user_password = self.request.get("password")
        self.verify_password = self.request.get("verify")
        self.user_email = self.request.get("email")

        params = dict(username=self.username, user_email=self.user_email)

        if not valid_username(self.username):
            params["username_error"] = "That is not valid username."
            have_error = True

        if not valid_password(self.user_password):
            params["password_error"] = "That is not valid password."
            have_error = True
        elif self.user_password != self.verify_password:
            params["verify_error"] = "Your password input does not match."
            have_error = True

        if not valid_email(self.user_email):
            params["email_error"] = "Your email is not valid."
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(SignUpHandler):

    def done(self):
        # make sure user not already exists
        u = User.by_name(self.username)
        if u:
            msg = "You already exist as a user."
            self.render("signup.html", signup_error=msg)
        else:
            u = User.register(
                self.username, self.user_password, self.user_email)
            u.put()

            self.login(u)
            self.redirect("/blog")


class Login(Handler):

    def get(self):
        uid = self.read_secure_cookie("user_id")
        user = uid and User.by_id(int(uid))
        if user:
            username = user.name
        else:
            username = ""
        self.render("login.html", username=username)

    def post(self):
        username = self.request.get("username")
        user_password = self.request.get("password")

        u = User.login(username, user_password)

        if u:
            self.login(u)
            self.redirect("/blog")
        else:
            msg = "invalid login"
            self.render("login.html", error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect("/signup")


app = webapp2.WSGIApplication([
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/edit/([0-9]+)', EditPost),
    ('/blog/newpost', NewPost),
    ('/blog/newcomment/([0-9]+)', NewComment),
    ('/blog/likepost/([0-9]+)', LikeForPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/deletepost', DeletePost),
], debug=True)
