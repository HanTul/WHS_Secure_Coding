from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
import random

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    nickname = db.Column(db.String(30), unique=True, nullable=True)
    profile_img = db.Column(db.String(255), default="")
    intro = db.Column(db.Text, default="")
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
    account_number = db.Column(db.String(20), unique=True)
    balance = db.Column(db.Integer, default=0)

    def set_password(self, pw):
        self.pw_hash = bcrypt.generate_password_hash(pw).decode()

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.pw_hash, pw)

    def set_temp_password(self):
        temp_password = "".join(random.choices("0123456789", k=6))
        self.set_password(temp_password)
        return temp_password

    @property
    def profile_img_url(self):
        return self.profile_img or "/static/img/default.png"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image_paths = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    removed = db.Column(db.Boolean, default=False)

    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reports_cnt = db.Column(db.Integer, default=0)
    is_sold = db.Column(db.Integer, default=0)

    def owner_check(self, user):
        return user.is_authenticated and self.seller_id == user.id

    @property
    def image_path_list(self):
        return self.image_paths.split(",") if self.image_paths else []


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(10))
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


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


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="waiting_payment")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    buyer = db.relationship(
        "User", foreign_keys=[buyer_id], backref="transactions_bought"
    )
    seller = db.relationship(
        "User", foreign_keys=[seller_id], backref="transactions_sold"
    )
    product = db.relationship("Product", backref="transactions")
