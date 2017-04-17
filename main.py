import webapp2, jinja2, os, re
from google.appengine.ext import db
from models import Post, User   #import db classes from models.py
import hashutils                #provided file w/ func for password and cookie security

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class BlogHandler(webapp2.RequestHandler):
    """ Utility class for gathering various useful methods that are used by most request handlers """

    def get_posts(self, limit, offset):
        """ Get all posts ordered by creation date (descending) """
        query = Post.all().order('-created')            #Why not a GQL-style Query?
        return query.fetch(limit=limit, offset=offset)

    def get_posts_by_user(self, user, limit, offset):
        """
            Get all posts by a specific user, ordered by creation date (descending).
            The user parameter will be a User object.
        """

        # TODO - filter the query so that only posts by the given user
        return None

    def get_user_by_name(self, username):
        """ Get a user object from the db, based on their username """
        user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username) #string sub that plugs var into string
        if user:
            return user.get()       #Get all info for the requested user

    def login_user(self, user):
        """ Login a user specified by a User object user by setting a secure cookie """
        user_id = user.key().id()                           #Same wacky python-style query to get id out of key
        self.set_secure_cookie('user_id', str(user_id))     #uses a util method to ...

    def logout_user(self):
        """ Logout a user specified by a User object user """
        self.set_secure_cookie('user_id', '')               #log user out by changing user_id to '' in secure cookie

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)         #retrieve name of secure cookie
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)   #if cookie has a value for name, check in hashutils

    def set_secure_cookie(self, name, val):
        cookie_val = hashutils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))    #swap name for a secure version

    def initialize(self, *a, **kw):
        """
            A filter to restrict access to certain pages when not logged in.
            If the request path is in the global auth_paths list, then the user
            must be signed in to access the path/resource.
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')            #get user id from the cookie
        self.user = uid and User.get_by_id(int(uid))        #Check for that id in the db to see if they're logged in

        if not self.user and self.request.path in auth_paths:   #if not logged in as user and they are trying to view certain paths...
            self.redirect('/login')                         #then redirect

class IndexHandler(BlogHandler):
    """renders main blog page with list of all users"""
    def get(self):
        """ List all blog users """
        users = User.all()                          #query all user entities
        t = jinja_env.get_template("index.html")
        response = t.render(users = users)
        self.response.write(response)

class BlogIndexHandler(BlogHandler):
    """render page of posts for specifc user, 5 at a time"""
    # number of blog posts per page to display
    page_size = 5

    def get(self, username=""):

        # If request is for a specific page, set page number and offset accordingly
        page = self.request.get("page")
        offset = 0
        page = page and int(page)
        if page:
            offset = (int(page) - 1) * self.page_size
        else:
            page = 1

        # Fetch posts for all users, or a specific user, depending on request parameters
        if username:
            user = self.get_user_by_name(username)
            posts = self.get_posts_by_user(user, self.page_size, offset)
        else:
            posts = self.get_posts(self.page_size, offset)

        # determine next/prev page numbers for navigation links
        if page > 1:
            prev_page = page - 1
        else:
            prev_page = None

        if len(posts) == self.page_size and Post.all().count() > offset+self.page_size:
            next_page = page + 1
        else:
            next_page = None

        # render the page
        t = jinja_env.get_template("blog.html")
        response = t.render(
                    posts=posts,
                    page=page,
                    page_size=self.page_size,
                    prev_page=prev_page,
                    next_page=next_page,
                    username=username)
        self.response.out.write(response)

class NewPostHandler(BlogHandler):

    def render_form(self, title="", body="", error=""):
        """ Render the new post form with or without an error, based on parameters """
        t = jinja_env.get_template("newpost.html")
        response = t.render(title=title, body=body, error=error)
        self.response.out.write(response)

    def get(self):
        self.render_form()

    def post(self):
        """ Create a new blog post if possible. Otherwise, return with an error message """
        title = self.request.get("title")
        body = self.request.get("body")

        if title and body:

            # create a new Post object and store it in the database
            post = Post(
                title=title,
                body=body,
                author=self.user)
            post.put()

            # get the id of the new post, so we can render the post's page (via the permalink)
            id = post.key().id()
            self.redirect("/blog/%s" % id)
        else:
            error = "we need both a title and a body!"
            self.render_form(title, body, error)

class ViewPostHandler(BlogHandler):

    def get(self, id):
        """ Render a page with post determined by the id (via the URL/permalink) """

        post = Post.get_by_id(int(id))
        if post:
            t = jinja_env.get_template("post.html")
            response = t.render(post=post)
        else:
            error = "there is no post with id %s" % id      #Error for id with no corresponding post
            t = jinja_env.get_template("404.html")
            response = t.render(error=error)

        self.response.out.write(response)

class SignupHandler(BlogHandler):

    def validate_username(self, username):
        """Use regex to validate the username"""
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            return username
        else:
            return ""

    def validate_password(self, password):
        """Use regex to validate password"""
        PWD_RE = re.compile(r"^.{3,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        """Simple check to see if both passwords match"""
        if password == verify:
            return verify

    def validate_email(self, email):

        # allow empty email field
        if not email:
            return ""

        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")   #If email is entered, then validate it
        if EMAIL_RE.match(email):
            return email

    def get(self):
        """Use the signup template to render the signup page with any errors if needed"""
        t = jinja_env.get_template("signup.html")
        response = t.render(errors={})
        self.response.out.write(response)

    def post(self):
        """
            Validate submitted data, creating a new user if all fields are valid.
            If data doesn't validate, render the form again with an error.

            This code is essentially identical to the solution to the Signup portion
            of the Formation assignment. The main modification is that we are now
            able to create a new user object and store it when we have valid data.
        """

        submitted_username = self.request.get("username")      #request user submitted data from the browser's post request
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")
        submitted_email = self.request.get("email")

        username = self.validate_username(submitted_username)   #run the validation fuc created at beginning of this class
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)
        email = self.validate_email(submitted_email)

        errors = {}                                             #Create empty dictionary for potential errors
        existing_user = self.get_user_by_name(username)         #Check to see if the submitted username already exists
        has_error = False

        if existing_user:                                       #1st verification step: if a user by that name exists, create an error
            errors['username_error'] = "A user with that username already exists"
            has_error = True
        elif (username and password and verify and (email is not None) ):   #If all user inputs check out...

            # create new user object and store it in the database, including username and hashed pw
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, pw_hash=pw_hash)
            user.put()

            # login our new user using the generic method from the BlogHandler
            self.login_user(user)
        else:
            has_error = True    #if there are errors, add them to errors dict

            if not username:
                errors['username_error'] = "That's not a valid username"

            if not password:
                errors['password_error'] = "That's not a valid password"

            if not verify:
                errors['verify_error'] = "Passwords don't match"

            if email is None:
                errors['email_error'] = "That's not a valid email"

        if has_error:
            t = jinja_env.get_template("signup.html")       #render signup with error messages
            response = t.render(username=username, email=email, errors=errors)
            self.response.out.write(response)
        else:
            self.redirect('/blog/newpost')                  #After successful and signup and login, redirect to newpost

class LoginHandler(BlogHandler):

    # TODO - The login code here is mostly set up for you, but there isn't a template to log in

    def render_login_form(self, error=""):
        """ Render the login form with or without an error, based on parameters """
        t = jinja_env.get_template("login.html")
        response = t.render(error=error)
        self.response.out.write(response)

    def get(self):
        self.render_login_form()

    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        # get the user from the database
        user = self.get_user_by_name(submitted_username)

        if not user:
            self.render_login_form(error="Invalid username")
        elif hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.login_user(user)
            self.redirect('/blog/newpost')
        else:
            self.render_login_form(error="Invalid password")

class LogoutHandler(BlogHandler):

    def get(self):
        self.logout_user()
        self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/blog', BlogIndexHandler),
    ('/blog/newpost', NewPostHandler),
    webapp2.Route('/blog/<id:\d+>', ViewPostHandler),
    webapp2.Route('/blog/<username:[a-zA-Z0-9_-]{3,20}>', BlogIndexHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)

# A list of paths that a user must be logged in to access
auth_paths = [
    '/blog/newpost'
]
