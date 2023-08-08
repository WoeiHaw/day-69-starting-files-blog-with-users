from datetime import date

import flask
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    author = relationship("User", back_populates='blog_posts')
    comments = relationship("Comment", back_populates='parent_post')

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    blog_posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates='author')

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'),nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.String(250), nullable=False)


# TODO: Create a User table for all your registered users.


with app.app_context():
    db.create_all()


def admin_only(func):
    @wraps(func)

    def wrapper(*args, **kwargs):

        if current_user.is_authenticated:
            if current_user.id == 1:
                return func(*args, **kwargs)
            else:
                abort(403)
        else:
            abort(403)

        abort(403)

    return wrapper


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        password = generate_password_hash(password=request.form['password'],
                                          method='pbkdf2:sha256',
                                          salt_length=8)
        new_user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=password
        )
        user_check = db.session.execute(db.select(User).where(User.email == new_user.email)).scalar()

        if user_check != None:
            print("hi")
            flash("Email already exist, please login")
            return redirect(url_for("login"))
        else:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, is_login=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        print(user)
        if user != None:
            if (check_password_hash(user.password, password)):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Your email or password is incorrect")
                return redirect(url_for("login"))
        else:
            flash("Your email or password is incorrect")
            return redirect(url_for("login"))
    return render_template("login.html", form=form, is_login=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))

    posts = result.scalars().all()


    return render_template("index.html", all_posts=posts, is_login=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods =["GET","POST"])
def show_post(post_id):
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)

    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login to comment")
            return redirect(url_for('login'))

        new_comment = Comment(
            author_id=current_user.id,
            post_id=post_id,
            text=form.body.data
        )
        db.session.add(new_comment)
        db.session.commit()
    comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars()
    return render_template("post.html", post=requested_post, is_login=current_user.is_authenticated, form=form,
                           comments = comments, gravatar=gravatar)


# TODO: Use a decorator so only an admin user can create a new post


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_login=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, is_login=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', is_login=current_user.is_authenticated))


@app.route("/about")
def about():
    return render_template("about.html", is_login=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", is_login=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)
