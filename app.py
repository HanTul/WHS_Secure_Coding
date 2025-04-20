import os, secrets, pathlib
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    abort,
    g,
    send_from_directory,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect

from models import db, bcrypt, User, Product, Report, Message
from forms import RegisterForm, LoginForm, ProductForm
from utils import time_ago
from sqlalchemy import func
from random import randint

BASE_DIR = pathlib.Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "img"
ALLOWED = {"png", "jpg", "jpeg", "gif"}

user_current_room = {}
user_sid_map = {}  # {user_id: sid}


def _allowed(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED


def room_id(a, b):
    return f"dm-{min(a,b)}-{max(a,b)}"


def emit_refresh(user_id: int):
    if not user_id:
        return
    previews = get_recent_chats(user_id)

    # 미리보기 전체 갱신
    emit(
        "dm_preview_update",
        [
            {
                "partner_id": p.partner_id,
                "username": p.partner_name,
                "product_id": p.product_id or 0,
                "product_name": p.product_name,
                "last_msg": p.last_message,
                "time": p.last_time.isoformat() + "Z",
                "read": p.is_read,
                "link": url_for(
                    "dm_chat", partner_id=p.partner_id, item=p.product_id or None
                ),
            }
            for p in previews
        ],
        namespace="/",  # <- 명시해줘야 클라이언트가 인식 잘함
        room=f"user-{user_id}",
    )

    # 최신 메시지 하나만 갱신
    if previews:
        p = previews[0]
        emit(
            "dm_refresh",
            {
                "partner_id": p.partner_id,
                "partner_name": p.partner_name,
                "product_id": p.product_id or 0,
                "product_name": p.product_name,
                "snippet": p.last_message[:30],
                "time": p.last_time.isoformat() + "Z",
                "read": p.is_read,
            },
            namespace="/",
            room=f"user-{user_id}",
        )


def time_diff_string(dt):
    now = datetime.utcnow()
    diff = now - dt
    s = diff.total_seconds()
    if s < 60:
        return "방금 전"
    if s < 3600:
        return f"{int(s//60)}분 전"
    if s < 86400:
        return f"{int(s//3600)}시간 전"
    return f"{int(s//86400)}일 전"


def get_recent_chats(user_id):
    msgs = (
        Message.query.filter(
            ((Message.sender_id == user_id) | (Message.receiver_id == user_id))
            & (Message.receiver_id != None)
        )
        .order_by(Message.created_at.desc())
        .all()
    )

    seen, previews = set(), []
    for m in msgs:
        if not m.sender or not m.receiver:
            continue
        partner = m.receiver if m.sender_id == user_id else m.sender
        key = (partner.id, m.product_id)
        if key in seen:
            continue
        seen.add(key)
        previews.append(
            type(
                "ChatPreview",
                (),
                {
                    "partner_id": partner.id,
                    "partner_name": partner.username,
                    "product_id": m.product_id or 0,
                    "product_name": (
                        Product.query.get(m.product_id).name
                        if m.product_id
                        else "(상품없음)"
                    ),
                    "last_message": m.content,
                    "last_time": m.created_at,
                    "is_read": m.receiver_id != user_id or m.is_read,
                },
            )()
        )
    return previews


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(16)),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL")
        or f"sqlite:///{BASE_DIR/'app.db'}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(app)
    bcrypt.init_app(app)
    CSRFProtect(app)
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    lm = LoginManager(app)
    lm.login_view = "login"
    app.jinja_env.globals["time_ago"] = time_ago

    @lm.user_loader
    def load_user(uid):
        return User.query.get(int(uid))

    @app.template_filter("timeago")
    def _timeago(dt):
        return time_diff_string(dt)

    @app.before_request
    def before_request():
        g.dm_unread = 0
        if current_user.is_authenticated:
            g.dm_unread = Message.query.filter_by(
                receiver_id=current_user.id, is_read=False
            ).count()
            g.chat_previews = [
                {
                    "partner_id": cp.partner_id,
                    "username": cp.partner_name,
                    "product_id": cp.product_id,
                    "product_name": cp.product_name,
                    "last_msg": cp.last_message,
                    "time": time_diff_string(cp.last_time),
                    "read": cp.is_read,
                }
                for cp in get_recent_chats(current_user.id)
            ]
        else:
            g.chat_previews = []

    @app.route("/")
    def index():
        prods = Product.query.filter_by(removed=False).order_by(
            Product.created_at.desc()
        )
        return render_template("index.html", products=prods)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter_by(username=form.username.data).first():
                flash("이미 존재하는 아이디입니다.", "danger")
                return redirect(url_for("register"))

            nickname = f"user{randint(10000, 99999)}"
            while User.query.filter_by(nickname=nickname).first():
                nickname = f"user{randint(10000, 99999)}"

            u = User(username=form.username.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash("가입 완료! 로그인하세요.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            u = User.query.filter_by(username=form.username.data).first()
            if u and u.check_password(form.password.data) and not u.is_suspend:
                login_user(u)
                return redirect(url_for("index"))
            flash("로그인 실패 또는 정지된 계정입니다.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/products/new", methods=["GET", "POST"])
    @login_required
    def product_new():
        form = ProductForm()
        if form.validate_on_submit():
            files = request.files.getlist("image")
            paths = []
            for f in files:
                if f and _allowed(f.filename):
                    fname = secure_filename(f.filename)
                    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                    f.save(UPLOAD_DIR / fname)
                    paths.append(f"/static/img/{fname}")
            if not paths:
                flash("이미지는 최소 1장 이상 업로드해야 합니다.", "danger")
                return redirect(url_for("product_new"))
            p = Product(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                image_paths=",".join(paths),
                seller=current_user,
            )
            db.session.add(p)
            db.session.commit()
            flash("상품이 등록되었습니다.", "success")
            return redirect(url_for("index"))
        return render_template("product_new.html", form=form)

    @app.route("/products/<int:pid>")
    def product_detail(pid):
        p = Product.query.get_or_404(pid)
        return render_template("product_detail.html", p=p)

    @app.route("/my/products")
    @login_required
    def my_products():
        items = Product.query.filter_by(seller_id=current_user.id).all()
        return render_template("my_products.html", items=items)

    @app.route("/products/<int:pid>/edit", methods=["GET", "POST"])
    @login_required
    def product_edit(pid):
        p = Product.query.get_or_404(pid)
        if not p.owner_check(current_user):
            abort(403)
        form = ProductForm(obj=p)
        if form.validate_on_submit():
            form.populate_obj(p)
            db.session.commit()
            flash("상품 정보가 수정되었습니다.", "success")
            return redirect(url_for("my_products"))
        return render_template("product_edit.html", form=form, p=p)

    @app.route("/products/<int:pid>/delete", methods=["POST"])
    @login_required
    def product_delete(pid):
        p = Product.query.get_or_404(pid)
        if not p.owner_check(current_user):
            abort(403)
        p.removed = True
        db.session.commit()
        flash("상품이 삭제(숨김)되었습니다.", "info")
        return redirect(url_for("my_products"))

    @app.route("/report/<target_type>/<int:tid>", methods=["POST"])
    @login_required
    def report(target_type, tid):
        reason = request.form.get("reason", "").strip() or "No reason"
        rpt = Report(
            reporter_id=current_user.id,
            target_type=target_type,
            target_id=tid,
            reason=reason,
        )
        db.session.add(rpt)
        db.session.commit()
        if target_type == "product":
            prod = Product.query.get(tid)
            prod.reports_cnt += 1
            if prod.reports_cnt >= 5:
                prod.removed = True
        elif target_type == "user":
            cnt = Report.query.filter_by(target_type="user", target_id=tid).count()
            if cnt >= 5:
                User.query.get(tid).is_suspend = True
        db.session.commit()
        flash("신고가 접수되었습니다.", "info")
        return redirect(request.referrer or url_for("index"))

    @app.route("/admin")
    @login_required
    def admin():
        if not current_user.is_admin:
            abort(403)
        reports = Report.query.filter_by(resolved=False).all()
        return render_template("admin.html", reports=reports)

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def my_profile():
        if request.method == "POST":
            # 비밀번호 변경일 경우
            if "old_password" in request.form:
                old_pw = request.form.get("old_password", "")
                new_pw = request.form.get("new_password", "")
                if not current_user.check_password(old_pw):
                    flash("기존 비밀번호가 일치하지 않습니다.", "danger")
                else:
                    current_user.set_password(new_pw)
                    db.session.commit()
                    flash("비밀번호가 변경되었습니다.", "success")

            # 프로필 정보 수정일 경우
            else:
                nickname = request.form.get("nickname", "").strip()
                intro = request.form.get("intro", "").strip()
                file = request.files.get("profile_img")

                # 닉네임 중복 체크
                if nickname != current_user.nickname:
                    exists = User.query.filter(
                        User.nickname == nickname, User.id != current_user.id
                    ).first()
                    if exists:
                        flash("이미 사용 중인 닉네임입니다.", "danger")
                        return redirect(url_for("my_profile"))
                    current_user.nickname = nickname

                current_user.intro = intro

                # 이미지 저장
                if file and file.filename:
                    ext = file.filename.rsplit(".", 1)[-1].lower()
                    if ext in {"jpg", "jpeg", "png", "gif"}:
                        fname = secure_filename(file.filename)
                        path = os.path.join("static", "img", fname)
                        file.save(path)
                        current_user.profile_img = "/" + path.replace("\\", "/")

                db.session.commit()
                flash("프로필이 저장되었습니다.", "success")

        return render_template("my_profile.html", user=current_user)

    @app.route("/profile/<nickname>")
    def view_profile(nickname):
        u = User.query.filter_by(nickname=nickname).first_or_404()
        return render_template("view_profile.html", user=u)

    @app.route("/check_nickname", methods=["POST"])
    def check_nickname():
        nickname = request.form.get("nickname", "").strip()
        if not nickname:
            return {"valid": False, "msg": "닉네임을 입력해주세요."}
        exists = User.query.filter_by(nickname=nickname).first()
        return {
            "valid": not bool(exists),
            "msg": "사용 가능" if not exists else "이미 사용 중입니다.",
        }

    # ───── socket handlers ─────

    @socketio.on("connect")
    def handle_connect():
        if current_user.is_authenticated:
            user_sid_map[current_user.id] = request.sid
            join_room(f"user_{current_user.id}")
            emit_refresh(current_user.id)

    @socketio.on("disconnect")
    def handle_disconnect():
        if current_user.is_authenticated:
            leave_room(f"user-{current_user.id}")

    @socketio.on("current_room")
    def handle_current_room(data):
        if current_user.is_authenticated:
            user_current_room[current_user.id] = data.get("room")

    @socketio.on("load_public_history")
    def load_public_history():
        if not current_user.is_authenticated:
            return
        msgs = (
            Message.query.filter(Message.receiver_id == None)
            .order_by(Message.created_at.asc())
            .limit(100)
            .all()
        )
        emit(
            "public_history",
            [
                {
                    "msg": m.content,
                    "sender_id": m.sender_id,
                    "username": m.sender.username,
                    "time": m.created_at.isoformat(),
                }
                for m in msgs
            ],
        )

    @socketio.on("message")
    def on_message(text):
        if not current_user.is_authenticated:
            return
        m = Message(sender_id=current_user.id, content=text)
        db.session.add(m)
        db.session.commit()
        emit(
            "message",
            {
                "username": current_user.username,
                "sender_id": current_user.id,
                "msg": text,
                "time": m.created_at.isoformat() + "Z",
            },
            broadcast=True,
        )

    @socketio.on("join_dm")
    def on_join_dm(data):
        join_room(data["room"])

    @socketio.on("request_dm_preview")
    def send_dm_preview():
        if not current_user.is_authenticated:
            return
        previews = []
        for cp in get_recent_chats(current_user.id):
            previews.append(
                {
                    "partner_id": cp.partner_id,
                    "username": cp.partner_name,
                    "product_id": cp.product_id,
                    "product_name": cp.product_name,
                    "last_msg": cp.last_message,
                    "time": cp.last_time.isoformat(),  # <-- 여기 수정됨
                    "read": cp.is_read,
                    "link": url_for(
                        "dm_chat", partner_id=cp.partner_id, item=cp.product_id or None
                    ),
                }
            )
        emit("dm_preview_update", previews)

    @socketio.on("dm_message")
    def on_dm_message(data):
        room = data["room"]
        text = data["msg"].strip()
        prod_id = data.get("product_id")
        uid1, uid2 = map(int, room.split("-")[1:])
        sender_id = current_user.id
        target_id = uid2 if sender_id == uid1 else uid1

        # 1. DB 저장
        m = Message(
            sender_id=sender_id,
            receiver_id=target_id,
            product_id=prod_id,
            content=text,
            is_read=False,
        )
        db.session.add(m)
        db.session.commit()

        # 2. 실시간 메시지 송수신
        emit(
            "dm_message",
            {
                "user": current_user.username,
                "sender_id": sender_id,
                "msg": text,
                "product_id": prod_id or 0,
                "time": m.created_at.isoformat() + "Z",
            },
            room=room,
        )

        # 3. 상대방이 다른 방에 있는 경우에만 알림 전송
        if user_current_room.get(target_id) != room:
            prod = Product.query.get(prod_id) if prod_id else None
            emit(
                "dm_notify",
                {
                    "sender_id": sender_id,
                    "partner_id": sender_id,
                    "partner_name": current_user.username,
                    "product_id": prod.id if prod else 0,
                    "product_name": prod.name if prod else "(상품없음)",
                    "snippet": text[:30],
                    "time": m.created_at.isoformat() + "Z",  # ← 여기 Z 보장
                },
                room=f"user-{target_id}",
            )

        # 4. 🔥 dm_refresh - 실시간 미리보기 한 줄씩 직접 전송
        prod = Product.query.get(prod_id) if prod_id else None
        emit(
            "dm_refresh",
            {
                "partner_id": target_id,
                "partner_name": User.query.get(target_id).username,
                "product_id": prod.id if prod else 0,
                "product_name": prod.name if prod else "(상품없음)",
                "snippet": text[:30],
                "time": m.created_at.isoformat() + "Z",
                "read": True,
            },
            room=f"user-{sender_id}",
        )

        emit(
            "dm_refresh",
            {
                "partner_id": sender_id,
                "partner_name": current_user.username,
                "product_id": prod.id if prod else 0,
                "product_name": prod.name if prod else "(상품없음)",
                "snippet": text[:30],
                "time": m.created_at.isoformat() + "Z",
                "read": False,
            },
            room=f"user-{target_id}",
        )

        # 5. (선택) 전체 미리보기 새로고침도 유지
        emit_refresh(sender_id)
        emit_refresh(target_id)

    @app.route("/chat/<int:partner_id>")
    @login_required
    def dm_chat(partner_id):
        partner = User.query.get_or_404(partner_id)
        if partner.id == current_user.id:
            abort(400)
        room = room_id(current_user.id, partner.id)

        # 읽음 처리
        Message.query.filter_by(
            sender_id=partner.id, receiver_id=current_user.id, is_read=False
        ).update({"is_read": True}, synchronize_session="fetch")
        db.session.commit()

        prod_id = request.args.get("item", type=int)
        product = None
        if prod_id:
            cand = Product.query.get(prod_id)
            if cand and cand.seller_id == partner.id:
                product = cand

        if not product:
            last = (
                Message.query.filter(
                    (
                        (Message.sender_id == current_user.id)
                        & (Message.receiver_id == partner.id)
                    )
                    | (
                        (Message.sender_id == partner.id)
                        & (Message.receiver_id == current_user.id)
                    )
                )
                .filter(Message.product_id.is_not(None))
                .order_by(Message.created_at.desc())
                .first()
            )
            if last:
                product = Product.query.get(last.product_id)

        history = (
            Message.query.filter(
                (
                    (Message.sender_id == current_user.id)
                    & (Message.receiver_id == partner.id)
                )
                | (
                    (Message.sender_id == partner.id)
                    & (Message.receiver_id == current_user.id)
                )
            )
            .order_by(Message.created_at.asc())
            .limit(100)
            .all()
        )

        return render_template(
            "dm_chat.html",
            partner=partner,
            room=room,
            history=history,
            product=product,
        )

    return app, socketio


if __name__ == "__main__":
    app, socketio = create_app()
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            admin = User(username="admin", is_admin=True)
            admin.set_password("1")
            db.session.add(admin)
            db.session.commit()
            print("admin(admin / 1) 계정이 생성되었습니다.")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
