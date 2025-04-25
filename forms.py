from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    TextAreaField,
    IntegerField,
    FileField,
    SelectField,
)
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange, Regexp
from flask_wtf.file import FileAllowed, FileRequired, MultipleFileField


class RegisterForm(FlaskForm):
    username = StringField(
        "아이디",
        validators=[
            DataRequired(),
            Length(3, 30),
            Regexp(
                r"^[a-zA-Z0-9_]+$",
                message="아이디는 영문, 숫자, 언더스코어만 가능합니다.",
            ),
        ],
    )
    password = PasswordField(
        "비밀번호",
        validators=[
            DataRequired(),
            Length(8, 30),
            Regexp(
                r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$",
                message="비밀번호는 영문과 숫자를 포함해야 합니다.",
            ),
        ],
    )
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
    image = MultipleFileField("이미지 파일")
    is_sold = SelectField(
        "판매 상태", choices=[("0", "판매중"), ("1", "판매완료"), ("2", "거래중")]
    )
    removed = SelectField("공개 상태", choices=[("0", "공개"), ("1", "숨김")])
