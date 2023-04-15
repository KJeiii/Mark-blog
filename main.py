from flask import Flask, render_template, redirect, url_for, flash, jsonify, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy.orm import relationship
# from sqlalchemy import ForeignKey
# from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
# Base = declarative_base()
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    #create relational table
    posts = db.relationship('BlogPost', back_populates = 'author')
    comments = db.relationship('Comment', back_populates = 'author')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #create relational table
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates= 'posts')
    comments = db.relationship('Comment', back_populates = 'post')

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)

    #create relational table
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = db.relationship('BlogPost', back_populates='comments')

# with app.app_context():
#     # db.drop_all()
#     db.create_all()


##Create forms using Flask_wtform and WTForm
class Register_form(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(),Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    name = StringField('Name', validators = [DataRequired()])
    submit = SubmitField('Sign me up!')

class Login_form(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Let me in!')

login_manager = LoginManager()
login_manager.init_app(app)

##Create flask_login
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)


##Create admin_only decorator
def admin_only(function):
    @wraps(function)
    def inner_function(*arg,**kwarg):
        if current_user.id == 1:
            return function(*arg,**kwarg)
        abort(403)
    return inner_function

##Create user img by Flask_Gravatar
gravatar = Gravatar(
    app,
    size=50,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=True,
    base_url=None
)

##Create web
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated and current_user.id == 1:
        return render_template("index.html", all_posts = posts, admin = True)    
    return render_template("index.html", all_posts = posts)


@app.route('/register', methods = ['POST','GET'])
def register():
    form = Register_form()
    if form.validate_on_submit():
        try:
            db.one_or_404(db.select(User).filter_by(email=form.email.data))
        except:
            user = User(
                email = form.email.data,
                password = generate_password_hash(form.password.data,"pbkdf2:sha256",8),
                name = form.name.data
            )
            db.session.add(user)
            db.session.commit()

            login_user(user, remember=True)
            return redirect(url_for('get_all_posts'))
        else:
            flash('This email has already singed up, please login directly.')
            return redirect(url_for('login'))
        
    return render_template("register.html", form = form)


@app.route('/login', methods = ['POST','GET'])
def login():
    form = Login_form()
    if form.validate_on_submit():
        try: 
            db.one_or_404(db.select(User).filter_by(email=form.email.data))
        
        except: 
            flash('This email has not singed up yet, please register first.')
            return redirect(url_for('login'))
        
        else:
            if not check_password_hash(db.one_or_404(db.select(User).filter_by(email=form.email.data)).password,form.password.data):
                flash('Password is not correct, please try again.')
                return redirect(url_for('login'))

            user = db.one_or_404(db.select(User).filter_by(email=form.email.data))
            login_user(user, remember=True)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["POST","GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    # comments = Comment.query.all()
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text = form.comment.data,
            author_id = current_user.id,
            post_id = post_id
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form = form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods = ["POST","GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(debug=True)