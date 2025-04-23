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
    jsonify,
    request,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect, CSRFError

from models import db, bcrypt, User, Product, Report, Message
from forms import RegisterForm, LoginForm, ProductForm
from utils import time_ago
from sqlalchemy import func
from random import randint
from models import Transaction, Notification, Message, User, Product
import random

BASE_DIR = pathlib.Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "img"
ALLOWED = {"png", "jpg", "jpeg", "gif"}

user_current_room = {}
user_sid_map = {}  # {user_id: sid}


def _allowed(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED


def room_id(a, b, product_id=None):
    base = f"dm-{min(a, b)}-{max(a, b)}"
    return f"{base}-{product_id}" if product_id else base


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
            & (Message.product_id != None)
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
                    "product_id": m.product_id,
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


def create_system_message(room, content, buyer_id, seller_id, product_id=None):
    system_message = Message(
        sender_id=None,
        receiver_id=None,
        product_id=product_id,
        content=f"[시스템] {content}",
    )
    db.session.add(system_message)
    db.session.commit()

    socketio.emit(
        "dm_message",
        {
            "user": "시스템",
            "sender_id": None,
            "msg": f"[시스템] {content}",
            "product_id": product_id or 0,
            "time": system_message.created_at.isoformat() + "Z",
            "is_system": True,  # 👈 추가
        },
        room=room,
    )


def send_transaction_notification(
    receiver_id, content, partner_id, product, is_system=False
):
    snippet_raw = content

    notif = Notification(
        receiver_id=receiver_id,
        sender_id=partner_id,
        partner_name=User.query.get(partner_id).nickname
        or User.query.get(partner_id).username,
        product_id=product.id,
        product_name=product.name,
        snippet=snippet_raw[:30],
    )
    db.session.add(notif)
    db.session.commit()

    socketio.emit(
        "dm_notify",
        {
            "sender_id": partner_id,
            "partner_id": partner_id,
            "partner_name": notif.partner_name,
            "product_id": product.id,
            "product_name": product.name,
            "snippet": snippet_raw[:30],
            "time": notif.timestamp.isoformat() + "Z",
        },
        room=f"user_{receiver_id}",
    )


def update_transaction_status(transaction_id, action, current_user_id):
    t = Transaction.query.get_or_404(transaction_id)
    product = Product.query.get(t.product_id)
    room = room_id(t.buyer_id, t.seller_id)

    if action == "pay" and t.status == "waiting_payment":
        t.status = "paid"
        db.session.commit()
        create_system_message(
            room, "구매자가 송금을 완료했습니다.", t.buyer_id, t.seller_id, t.product_id
        )
        send_transaction_notification(
            t.seller_id, "[시스템] 구매자가 송금을 완료했습니다.", t.buyer_id, product
        )

    elif action == "ship" and t.status == "paid":
        t.status = "shipped"
        db.session.commit()
        create_system_message(
            room, "판매자가 발송을 완료했습니다.", t.buyer_id, t.seller_id, t.product_id
        )
        send_transaction_notification(
            t.buyer_id, "[시스템] 판매자가 발송을 완료했습니다.", t.seller_id, product
        )

    elif action == "receive" and t.status == "shipped":
        t.status = "received"
        # 판매자 balance 지급
        seller = User.query.get(t.seller_id)
        seller.balance = getattr(seller, "balance", 0) + t.amount
        product.is_sold = 1
        db.session.commit()
        create_system_message(
            room,
            "구매자가 수령을 확인했습니다. 판매자에게 정산이 완료되었습니다.",
            t.buyer_id,
            t.seller_id,
            t.product_id,
        )
        send_transaction_notification(
            t.seller_id, "[시스템] 구매자가 수령을 확인했습니다.", t.buyer_id, product
        )

    elif action == "cancel" and t.status in ("waiting_payment", "paid"):
        if t.status == "paid":
            # 환불 처리
            buyer = User.query.get(t.buyer_id)
            seller = User.query.get(t.seller_id)
            buyer.balance = getattr(buyer, "balance", 0) + t.amount
            seller.balance = getattr(seller, "balance", 0) - t.amount
        t.status = "canceled"
        db.session.commit()
        create_system_message(
            room, "거래가 취소되었습니다.", t.buyer_id, t.seller_id, t.product_id
        )
        send_transaction_notification(
            t.buyer_id, "[시스템] 거래가 취소되었습니다.", t.seller_id, product
        )
        send_transaction_notification(
            t.seller_id, "[시스템] 거래가 취소되었습니다.", t.buyer_id, product
        )
    else:
        abort(400, "잘못된 상태 변경 요청입니다.")


csrf = CSRFProtect()


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
    csrf.init_app(app)
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
        keyword = request.args.get("q", "").strip()

        if keyword:
            prods = (
                Product.query.filter(
                    Product.removed == False, Product.name.ilike(f"%{keyword}%")
                )
                .order_by(Product.created_at.desc())
                .all()
            )
        else:
            prods = (
                Product.query.filter_by(removed=False)
                .order_by(Product.created_at.desc())
                .all()
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

            # 🟢 계좌번호 랜덤 생성 (예: 8자리 숫자)
            account_number = str(randint(10000000, 99999999))
            while User.query.filter_by(account_number=account_number).first():
                account_number = str(randint(10000000, 99999999))

            u = User(
                username=form.username.data,
                nickname=nickname,
                account_number=account_number,  # 여기 추가!
            )
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
                return render_template("product_new.html", form=form)

            is_sold = form.is_sold.data == "1"
            removed = form.removed.data == "1"

            p = Product(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                image_paths=",".join(paths),
                is_sold=is_sold,
                removed=removed,
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
        seller_products = (
            Product.query.filter(
                Product.seller_id == p.seller_id,
                Product.id != p.id,
                Product.removed == False,
            )
            .order_by(Product.created_at.desc())
            .limit(4)
            .all()
        )
        return render_template(
            "product_detail.html", p=p, seller_products=seller_products
        )

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

        # ✅ GET 요청일 때만 선택 필드 초기화
        if request.method == "GET":
            form.is_sold.data = "1" if p.is_sold else "0"
            form.removed.data = "1" if p.removed else "0"

        if form.validate_on_submit():
            form.populate_obj(p)
            p.is_sold = form.is_sold.data == "1"
            p.removed = form.removed.data == "1"

            # ✅ 삭제 요청된 이미지 제외
            keep_images = set(p.image_path_list)
            deleted = set(request.form.getlist("delete_images"))
            keep_images -= deleted

            # ✅ 새 이미지 추가
            files = request.files.getlist("image")
            for f in files:
                if f and f.filename and "." in f.filename:
                    ext = f.filename.rsplit(".", 1)[1].lower()
                    if ext in {"jpg", "jpeg", "png", "gif"}:
                        fname = secure_filename(f.filename)
                        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                        f.save(UPLOAD_DIR / fname)
                        keep_images.add(f"/static/img/{fname}")

            # ✅ 업데이트된 이미지 목록 저장
            p.image_paths = ",".join(keep_images)

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

        # 신고 객체 생성
        rpt = Report(
            reporter_id=current_user.id,
            target_type=target_type,
            target_id=tid,
            reason=reason,
        )
        db.session.add(rpt)

        # 처리 분기
        if target_type == "product":
            prod = Product.query.get_or_404(tid)
            prod.reports_cnt += 1
            # 5회 이상이면 자동 숨김
            if prod.reports_cnt >= 5 and not prod.removed:
                prod.removed = True
                flash("해당 상품이 신고 누적으로 자동 숨김 처리되었습니다.", "warning")

        elif target_type == "user":
            total_reports = Report.query.filter_by(
                target_type="user", target_id=tid
            ).count()
            user = User.query.get_or_404(tid)
            # 5회 이상이면 자동 정지
            if total_reports >= 5 and not user.is_suspend:
                user.is_suspend = True
                flash("해당 유저가 신고 누적으로 자동 정지 처리되었습니다.", "warning")

        db.session.commit()
        flash("신고가 접수되었습니다.", "info")
        return redirect(request.referrer or url_for("index"))

    @app.route("/admin")
    @login_required
    def admin():
        if not current_user.is_admin:
            abort(403)

        reports = Report.query.filter_by(resolved=False).all()
        enriched_reports = []
        for r in reports:
            reporter = User.query.get(r.reporter_id)
            target_user = (
                User.query.get(r.target_id) if r.target_type == "user" else None
            )
            target_product = (
                Product.query.get(r.target_id) if r.target_type == "product" else None
            )
            enriched_reports.append(
                {
                    "id": r.id,
                    "reason": r.reason,
                    "created_at": r.created_at,
                    "target_type": r.target_type,
                    "resolved": r.resolved,
                    "reporter": reporter,
                    "target_user": target_user,
                    "target_product": target_product,
                }
            )

        users = User.query.all()
        products = Product.query.all()

        return render_template(
            "admin.html", reports=enriched_reports, users=users, products=products
        )

    @app.route("/admin/suspend_user/<int:uid>", methods=["POST"])
    @login_required
    def suspend_user(uid):
        if not current_user.is_admin:
            abort(403)
        u = User.query.get_or_404(uid)
        u.is_suspend = not u.is_suspend
        db.session.commit()
        flash("유저 상태 변경 완료", "info")
        return redirect(url_for("admin"))

    @app.route("/admin/toggle_product/<int:pid>", methods=["POST"])
    @login_required
    def toggle_product(pid):
        if not current_user.is_admin:
            abort(403)
        p = Product.query.get_or_404(pid)
        p.removed = not p.removed
        db.session.commit()
        flash("상품 상태 변경 완료", "info")
        return redirect(url_for("admin"))

    @app.route("/admin/resolve_report/<int:rid>", methods=["POST"])
    @login_required
    def resolve_report(rid):
        if not current_user.is_admin:
            abort(403)
        r = Report.query.get_or_404(rid)
        r.resolved = True
        db.session.commit()
        flash("신고 처리 완료", "info")
        return redirect(url_for("admin"))

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

    @app.route("/profile/<username>")
    def view_profile(username):
        u = User.query.filter_by(username=username).first_or_404()
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

    @app.route("/notif/read", methods=["POST"])
    @csrf.exempt
    @login_required
    def mark_notification_read():
        try:
            data = request.get_json(silent=False)
            pid = int(data.get("partner_id"))
            prod_id = int(data.get("product_id"))
        except Exception as e:
            return {"error": f"Invalid data: {e}"}, 400

        notifs = Notification.query.filter_by(
            receiver_id=current_user.id,
            sender_id=pid,
            product_id=prod_id,
            is_read=False,
        ).all()

        if not notifs:
            return {"error": "No matching notifications"}, 400

        for n in notifs:
            n.is_read = True
        db.session.commit()

        return {"ok": True}

    @app.route("/chat/<int:partner_id>")
    @login_required
    def dm_chat(partner_id):
        partner = User.query.get_or_404(partner_id)
        if partner.id == current_user.id:
            abort(400)
        room = None

        prod_id = request.args.get("item", type=int)
        product = None
        transaction = None

        if prod_id:
            product = Product.query.get_or_404(prod_id)
            # 구매자 기준 거래 찾기
            transaction = (
                Transaction.query.filter_by(
                    buyer_id=current_user.id,
                    seller_id=partner.id,
                    product_id=product.id,
                )
                .order_by(Transaction.created_at.desc())
                .first()
            )
            # 판매자 기준 거래 찾기
            if not transaction:
                transaction = (
                    Transaction.query.filter_by(
                        buyer_id=partner.id,
                        seller_id=current_user.id,
                        product_id=product.id,
                    )
                    .order_by(Transaction.created_at.desc())
                    .first()
                )

            room = room_id(current_user.id, partner.id, product.id)

            # 🟢 메세지 조회 시 product_id 도 필터링!
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
                    | (
                        (Message.sender_id == None) & (Message.receiver_id == None)
                    )  # 시스템 메시지
                )
                .filter(Message.product_id == product.id)
                .order_by(Message.created_at.asc())
                .all()
            )

        else:
            abort(400, "상품 정보가 필요합니다.")

        return render_template(
            "dm_chat.html",
            partner=partner,
            room=room,
            history=history,
            product=product,
            transaction=transaction,
        )

    @app.route("/transaction/<int:tid>/pay", methods=["POST"])
    @csrf.exempt
    @login_required
    def transaction_pay(tid):
        t = Transaction.query.get_or_404(tid)
        if current_user.id != t.buyer_id:
            abort(403)
        if t.status != "waiting_payment":
            return jsonify({"error": "잘못된 상태입니다."}), 400

        # 구매자 balance 차감
        if getattr(current_user, "balance", 0) < t.amount:
            return jsonify({"error": "잔액이 부족합니다."}), 400
        current_user.balance -= t.amount
        db.session.commit()

        update_transaction_status(tid, "pay", current_user.id)
        return jsonify({"ok": True})

    @app.route("/transaction/<int:tid>/ship", methods=["POST"])
    @csrf.exempt
    @login_required
    def transaction_ship(tid):
        t = Transaction.query.get_or_404(tid)
        if current_user.id != t.seller_id:
            abort(403)
        if t.status != "paid":
            return jsonify({"error": "잘못된 상태입니다."}), 400

        update_transaction_status(tid, "ship", current_user.id)
        return jsonify({"ok": True})

    @app.route("/transaction/<int:tid>/receive", methods=["POST"])
    @csrf.exempt
    @login_required
    def transaction_receive(tid):
        t = Transaction.query.get_or_404(tid)
        if current_user.id != t.buyer_id:
            abort(403)
        if t.status != "shipped":
            return jsonify({"error": "잘못된 상태입니다."}), 400

        update_transaction_status(tid, "receive", current_user.id)
        return jsonify({"ok": True})

    @app.route("/transaction/<int:tid>/cancel", methods=["POST"])
    @csrf.exempt
    @login_required
    def transaction_cancel(tid):
        t = Transaction.query.get_or_404(tid)
        if current_user.id not in (t.buyer_id, t.seller_id):
            abort(403)
        if t.status not in ("waiting_payment", "paid"):
            return jsonify({"error": "취소가 불가능한 상태입니다."}), 400

        update_transaction_status(tid, "cancel", current_user.id)
        return jsonify({"ok": True})

    @app.route("/transaction/start/<int:product_id>/<int:partner_id>", methods=["POST"])
    @csrf.exempt
    @login_required
    def transaction_start(product_id, partner_id):
        product = Product.query.get_or_404(product_id)
        partner = User.query.get_or_404(partner_id)

        if product.seller_id != partner.id:
            abort(400, "판매자 정보가 일치하지 않습니다.")
        if current_user.id == partner.id:
            abort(400, "본인과 거래할 수 없습니다.")

        # 🟥 수정된 부분: 상품 기준으로, 같은 상품에서만 중복 체크
        existing = Transaction.query.filter(
            Transaction.buyer_id == current_user.id,
            Transaction.seller_id == partner.id,
            Transaction.product_id == product.id,
            Transaction.status.in_(["waiting_payment", "paid", "shipped"]),
        ).first()

        if existing:
            return jsonify({"error": "이 상품은 이미 거래 중입니다."}), 400

        tran = Transaction(
            buyer_id=current_user.id,
            seller_id=partner.id,
            product_id=product.id,
            amount=product.price,
        )
        db.session.add(tran)
        product.is_sold = 2  # 거래중
        db.session.commit()

        room = room_id(tran.buyer_id, tran.seller_id, tran.product_id)
        create_system_message(
            room,
            "거래가 시작되었습니다.",
            tran.buyer_id,
            tran.seller_id,
            tran.product_id,
        )
        send_transaction_notification(
            tran.seller_id,
            "[시스템] 거래가 시작되었습니다.",
            tran.buyer_id,
            product,
            is_system=True,
        )
        send_transaction_notification(
            tran.buyer_id,
            "[시스템] 거래가 시작되었습니다.",
            tran.seller_id,
            product,
            is_system=True,
        )

        return jsonify({"ok": True, "transaction_id": tran.id})

    @app.route("/charge_balance", methods=["POST"])
    @csrf.exempt
    @login_required
    def charge_balance():
        try:
            amount = int(request.form.get("amount", 0))
            if amount <= 0:
                flash("금액은 1원 이상 입력하세요.", "danger")
            else:
                current_user.balance += amount
                db.session.commit()
                flash(
                    f"{amount}원이 충전되었습니다. 현재 잔고: {current_user.balance}원",
                    "success",
                )
        except Exception:
            flash("충전 중 오류가 발생했습니다.", "danger")
        return redirect(url_for("my_profile"))

    # 유저 삭제
    @app.route("/admin/delete_user/<int:uid>", methods=["POST"])
    @login_required
    def delete_user(uid):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(uid)
        if user.is_admin:
            flash("관리자는 삭제할 수 없습니다.", "danger")
        else:
            db.session.delete(user)
            db.session.commit()
            flash("유저가 삭제되었습니다.", "info")
        return redirect(url_for("admin"))

    # 임시 비밀번호 발급
    @app.route("/admin/temp_password/<int:uid>", methods=["POST"])
    @login_required
    def temp_password(uid):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(uid)
        temp_pw = secrets.token_hex(4)
        user.set_password(temp_pw)
        db.session.commit()
        flash(f"임시 비밀번호: {temp_pw}", "success")
        return redirect(url_for("admin"))

    # 상품 삭제
    @app.route("/admin/delete_product/<int:pid>", methods=["POST"])
    @login_required
    def delete_product(pid):
        if not current_user.is_admin:
            abort(403)
        product = Product.query.get_or_404(pid)
        db.session.delete(product)
        db.session.commit()
        flash("상품이 삭제되었습니다.", "info")
        return redirect(url_for("admin"))

    # ───── socket handlers ─────

    @socketio.on("connect")
    def handle_connect():
        if current_user.is_authenticated:
            user_sid_map[current_user.id] = request.sid
            join_room(f"user_{current_user.id}")
            socketio.emit("load_notifications", room=request.sid)
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
            .filter(Message.sender_id != None)
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
                    "time": m.created_at.isoformat() + "Z",
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
        uid1, uid2, product_id = map(int, room.split("-")[1:])

        sender_id = current_user.id
        target_id = uid2 if sender_id == uid1 else uid1

        m = Message(
            sender_id=sender_id,
            receiver_id=target_id,
            product_id=product_id,
            content=text,
            is_read=False,
        )
        db.session.add(m)
        db.session.commit()

        emit(
            "dm_message",
            {
                "user": current_user.username,
                "sender_id": sender_id,
                "msg": text,
                "product_id": product_id,
                "time": m.created_at.isoformat() + "Z",
            },
            room=room,
        )

        if user_current_room.get(target_id) != room:
            prod = Product.query.get(product_id) if product_id else None

            # ✅ 알림 DB 저장
            n = Notification(
                receiver_id=target_id,
                sender_id=sender_id,
                partner_name=current_user.nickname or current_user.username,
                product_id=prod.id if prod else 0,
                product_name=prod.name if prod else "(상품없음)",
                snippet=text[:30],
            )
            db.session.add(n)
            db.session.commit()

            # ✅ 알림 전송
            emit(
                "dm_notify",
                {
                    "sender_id": sender_id,
                    "partner_id": sender_id,
                    "partner_name": current_user.nickname or current_user.username,
                    "product_id": prod.id if prod else 0,
                    "product_name": prod.name if prod else "(상품없음)",
                    "snippet": text[:30],
                    "time": n.timestamp.isoformat() + "Z",  # ← 알림 저장된 시각 기준
                },
                room=f"user_{target_id}",
            )

        # 4. dm_refresh 양쪽 전송
        prod = Product.query.get(product_id) if product_id else None
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

        # 5. 전체 미리보기 새로고침
        emit_refresh(sender_id)
        emit_refresh(target_id)

    @socketio.on("load_notifications")
    def load_notifications():
        if not current_user.is_authenticated:
            return

        notifs = (
            Notification.query.filter_by(receiver_id=current_user.id, is_read=False)
            .order_by(Notification.timestamp.desc())
            .limit(30)
            .all()
        )

        emit(
            "notif_list",
            [
                {
                    "partner_id": n.sender_id,
                    "partner_name": n.partner_name,
                    "product_id": n.product_id,
                    "product_name": n.product_name,
                    "snippet": n.snippet,
                    "time": n.timestamp.isoformat() + "Z",
                }
                for n in notifs
            ],
            room=request.sid,  # ❗ socket.emit()에 응답이 도착하도록 보장
        )

    return app, socketio


app, socketio = create_app()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            admin = User(username="admin", is_admin=True)
            admin.set_password("1")
            db.session.add(admin)
            db.session.commit()
            print("admin(admin / 1) 계정이 생성되었습니다.")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
