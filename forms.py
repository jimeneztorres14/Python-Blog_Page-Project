from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users

class RegisterForm(FlaskForm):
    user_email = StringField("Email", validators=[DataRequired()])
    user_password = PasswordField("Password", validators=[DataRequired()])
    user_name = StringField("Name", validators=[DataRequired()])
    submit_button = SubmitField("Sign Me Up!")


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    login_email = StringField("Email", validators=[DataRequired()])
    login_password = PasswordField("Password", validators=[DataRequired()])
    submit_button = SubmitField("Let Me In!")


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit_button = SubmitField("Submit Comment")