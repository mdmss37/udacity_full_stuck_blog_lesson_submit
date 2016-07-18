import random
import string
import hashlib
import hmac

from google.appengine.ext import ndb
import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def blog_key(name="default"):
    return ndb.Key("blogs", name)


def users_key(group="default"):
    return ndb.Key("users", group)


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
    number_of_liked = ndb.IntegerProperty(required=True)
    like_post_id = ndb.IntegerProperty(required=True)
    liked_user_id_list = ndb.IntegerProperty(repeated=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
