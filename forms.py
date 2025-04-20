from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange


class RegisterForm(FlaskForm):
    username = StringField("아이디", validators=[DataRequired(), Length(3, 30)])
    password = PasswordField("비밀번호", validators=[DataRequired(), Length(6, 30)])
    confirm = PasswordField(
        "비밀번호 확인",
        validators=[EqualTo("password", "비밀번호가 일치하지 않습니다.")],
    )


class LoginForm(FlaskForm):
    username = StringField("아이디", validators=[DataRequired()])
    password = PasswordField("비밀번호", validators=[DataRequired()])


class ProductForm(FlaskForm):
    name = StringField("상품명", validators=[DataRequired(), Length(max=60)])
    description = TextAreaField("설명", validators=[DataRequired()])
    price = IntegerField("가격", validators=[DataRequired(), NumberRange(min=0)])
    image = FileField("이미지 파일")  # 간단 업로드 (선택)
