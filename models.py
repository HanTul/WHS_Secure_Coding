from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    nickname = db.Column(db.String(30), unique=True, nullable=True)  # ✅ 닉네임 추가
    profile_img = db.Column(db.String(255), default="")
    intro = db.Column(db.Text, default="")  # ✅ 한 줄 소개
    pw_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_suspend = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    products = db.relationship("Product", backref="seller", lazy=True)
    messages_sent = db.relationship(
        "Message", foreign_keys="Message.sender_id", backref="sender", lazy=True
    )
    messages_recv = db.relationship(
        "Message", foreign_keys="Message.receiver_id", backref="receiver", lazy=True
    )

    def set_password(self, pw):
        self.pw_hash = bcrypt.generate_password_hash(pw).decode()

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.pw_hash, pw)

    @property
    def profile_img_url(self):
        return self.profile_img or "/static/img/default.png"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image_paths = db.Column(db.Text)  # 쉼표로 구분된 이미지 경로 문자열

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    removed = db.Column(db.Boolean, default=False)

    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reports_cnt = db.Column(db.Integer, default=0)

    def owner_check(self, user):
        return user.is_authenticated and self.seller_id == user.id

    @property
    def image_path_list(self):
        return self.image_paths.split(",") if self.image_paths else []


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(10))  # 'user' | 'product'
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)  # ✅ 추가


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    partner_name = db.Column(db.String(50))
    product_id = db.Column(db.Integer)
    product_name = db.Column(db.String(100))
    snippet = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
