import io
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
from stages import N, TPL, stage_state

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=60)
app.teardown_appcontext(db.close)
db.init()

ROLES = {"admin": "Администратор", "okk": "Инженер ОКК", "prorab": "Прораб", "client": "Заказчик"}
ROLE_SHORT = {"admin": "администратор", "okk": "ОКК", "prorab": "прораб", "client": "заказчик"}
KZ = timezone(timedelta(hours=5))


def now():
    return datetime.now(KZ).strftime("%Y-%m-%d %H:%M:%S")


def ru_date(s):
    return f"{s[8:10]}.{s[5:7]}.{s[0:4]}" if s and len(s) >= 10 else ""


def pct(v):
    return f"{round(v, 1):.1f}".replace(".", ",") + "%"


app.jinja_env.filters["d"] = ru_date
app.jinja_env.filters["pct"] = pct
app.jinja_env.globals.update(TPL=TPL, N=N, ROLES=ROLES)


def norm_phone(p):
    d = re.sub(r"\D", "", p or "")
    if len(d) == 11 and d[0] == "8":
        d = "7" + d[1:]
    if len(d) == 10:
        d = "7" + d
    return "+" + d if len(d) == 11 else ""


# ---------- CSRF ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf_token


@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = db.q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if not g.user or g.user["status"] == "blocked":
            session.pop("uid", None)
            g.user = None
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(400, "Сессия устарела, обновите страницу")


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login"))
        if g.user["status"] != "active":
            return redirect(url_for("pending"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "admin":
            abort(403)
        return f(*a, **k)
    return w


def can(action):
    r = g.user["role"]
    return {"pr": r in ("prorab", "admin"), "okk": r in ("okk", "admin")}[action]


# ---------- доступ к объектам ----------
def complex_ids():
    if g.user["role"] == "admin":
        return [r["id"] for r in db.q("SELECT id FROM complexes")]
    return [r["complex_id"] for r in db.q("SELECT complex_id FROM access WHERE user_id=?", (g.user["id"],))]


def check_complex(cid):
    if cid not in complex_ids():
        abort(404)


def flat_or_404(fid):
    f = db.q("SELECT * FROM flats WHERE id=?", (fid,), one=True)
    if not f:
        abort(404)
    check_complex(f["complex_id"])
    return f


def in_list(ids):
    return "(" + ",".join(str(int(i)) for i in ids) + ")" if ids else "(0)"


# ---------- проценты ----------
def flat_stats(work_rows):
    """work_rows: строки works одной квартиры → (ОКК %, прораб %, принято, сдано, состояния этапов)."""
    by = {}
    for w in work_rows:
        by.setdefault(w["stage"], []).append(w["status"])
    states = [stage_state(by.get(i, [])) for i in range(N)]
    o = sum(1 for s in states if s == "ok")
    p = sum(1 for i in range(N) if by.get(i) and all(x in ("ok", "rv") for x in by[i]))
    sent = [bool(by.get(i)) and all(x in ("ok", "rv") for x in by[i]) for i in range(N)]
    return {"okk": o * 100 / N, "pr": p * 100 / N, "o": o, "p": p, "states": states, "sent": sent}


def complex_stats(cid):
    flats = db.q("SELECT * FROM flats WHERE complex_id=? ORDER BY id", (cid,))
    works = db.q("SELECT w.flat_id, w.stage, w.status FROM works w JOIN flats f ON f.id=w.flat_id WHERE f.complex_id=?", (cid,))
    by = {}
    for w in works:
        by.setdefault(w["flat_id"], []).append(w)
    out = []
    for f in flats:
        out.append({**f, **flat_stats(by.get(f["id"], []))})
    n = len(out) or 1
    return out, {"okk": sum(f["okk"] for f in out) / n, "pr": sum(f["pr"] for f in out) / n}


# ---------- шапка: задачи и уведомления ----------
def task_works():
    ids = complex_ids()
    base = ("SELECT w.*, f.number, f.complex_id, c.name AS cname FROM works w JOIN flats f ON f.id=w.flat_id "
            f"JOIN complexes c ON c.id=f.complex_id WHERE f.complex_id IN {in_list(ids)} ")
    if g.user["role"] in ("okk",):
        return db.q(base + "AND w.status='rv' ORDER BY w.date")
    if g.user["role"] == "admin":
        return db.q(base + "AND (w.status='rv' OR (w.status='wk' AND w.ret<>'')) ORDER BY w.date")
    if g.user["role"] == "prorab":
        return db.q(base + "AND w.status='wk' AND w.ret<>'' ORDER BY w.date")
    return []


@app.context_processor
def header_counts():
    if not g.get("user") or g.user["status"] != "active":
        return {}
    ids = complex_ids()
    unread = db.q(
        "SELECT COUNT(*) AS n FROM events e JOIN flats f ON f.id=e.flat_id "
        f"WHERE f.complex_id IN {in_list(ids)} AND e.created>? AND COALESCE(e.user_id,0)<>?",
        (g.user["notes_seen"] or "", g.user["id"]), one=True)["n"]
    return {"tasks_n": len(task_works()), "unread": unread}


def log(flat_id, stage, kind, text):
    db.x("INSERT INTO events(flat_id,stage,kind,text,user_id,created) VALUES(?,?,?,?,?,?)",
         (flat_id, stage, kind, text, g.user["id"], now()))


# ---------- регистрация и вход ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        phone = norm_phone(request.form.get("phone"))
        pw = request.form.get("password", "")
        role = request.form.get("role", "prorab")
        company = request.form.get("company", "").strip()[:120]
        if not name or not phone:
            flash("Укажите имя и номер телефона в формате +7 7XX XXX XX XX")
        elif len(pw) < 6:
            flash("Пароль — минимум 6 символов")
        elif role not in ("prorab", "okk", "client"):
            flash("Выберите роль")
        elif db.q("SELECT id FROM users WHERE phone=?", (phone,), one=True):
            flash("Этот номер уже зарегистрирован — войдите")
        else:
            first = db.q("SELECT COUNT(*) AS n FROM users", one=True)["n"] == 0
            uid = db.x("INSERT INTO users(name,phone,pw,role,status,company,created) VALUES(?,?,?,?,?,?,?)",
                       (name, phone, generate_password_hash(pw), "admin" if first else role,
                        "active" if first else "pending", company, now()), returning=True)
            db.commit()
            session.clear()
            session["uid"] = uid
            session.permanent = True
            if first:
                flash("Вы первый пользователь — назначены администратором")
                return redirect(url_for("admin_objects"))
            return redirect(url_for("pending"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = norm_phone(request.form.get("phone"))
        u = db.q("SELECT * FROM users WHERE phone=?", (phone,), one=True)
        if not u or not check_password_hash(u["pw"], request.form.get("password", "")):
            flash("Неверный номер или пароль")
        elif u["status"] == "blocked":
            flash("Доступ заблокирован администратором")
        else:
            session.clear()
            session["uid"] = u["id"]
            session.permanent = True
            return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/pending")
def pending():
    if not g.user:
        return redirect(url_for("login"))
    if g.user["status"] == "active":
        return redirect(url_for("home"))
    return render_template("pending.html")


# ---------- квартиры ----------
@app.route("/")
@login_required
def home():
    ids = complex_ids()
    cs = db.q(f"SELECT * FROM complexes WHERE id IN {in_list(ids)} ORDER BY id")
    cards = []
    for c in cs:
        flats, tot = complex_stats(c["id"])
        cards.append({**c, "n": len(flats), **tot})
    return render_template("home.html", cards=cards, nav="home")


@app.route("/c/<int:cid>")
@login_required
def flats(cid):
    check_complex(cid)
    c = db.q("SELECT * FROM complexes WHERE id=?", (cid,), one=True)
    fl, tot = complex_stats(cid)
    return render_template("flats.html", c=c, flats=fl, tot=tot, nav="home")


@app.route("/f/<int:fid>")
@login_required
def flat(fid):
    f = flat_or_404(fid)
    c = db.q("SELECT * FROM complexes WHERE id=?", (f["complex_id"],), one=True)
    works = db.q("SELECT * FROM works WHERE flat_id=? ORDER BY stage, idx", (fid,))
    st = flat_stats(works)
    photos = db.q("SELECT p.id, p.work_id FROM photos p JOIN works w ON w.id=p.work_id WHERE w.flat_id=? ORDER BY p.id", (fid,))
    pics = {}
    for p in photos:
        pics.setdefault(p["work_id"], []).append(p["id"])
    by_stage = {}
    for w in works:
        by_stage.setdefault(w["stage"], []).append(w)
    hist = {}
    for e in db.q("SELECT e.*, u.name AS uname FROM events e LEFT JOIN users u ON u.id=e.user_id WHERE e.flat_id=? ORDER BY e.id DESC", (fid,)):
        hist.setdefault(e["stage"], []).append(e)
    users = {u["id"]: u for u in db.q("SELECT id, name, role FROM users")}
    cards = []
    for i, (name, tw, photo_only) in enumerate(TPL):
        ws = by_stage.get(i, [])
        state = st["states"][i]
        callers = [users[w["sent_by"]] for w in ws if w["sent_by"] in users and w["status"] in ("rv", "ok")]
        returned = any(w["status"] == "wk" and w["ret"] for w in ws)
        cards.append({"i": i, "name": name, "works": ws, "photo_only": photo_only, "state": state,
                      "acc": sum(1 for w in ws if w["status"] == "ok"), "total": len(ws), "returned": returned,
                      "caller": ROLE_SHORT.get(callers[-1]["role"], "") if callers else "",
                      "since": max((w["date"] for w in ws if w["date"]), default="")})
    cards.sort(key=lambda c: (c["state"] == "ok", c["i"]))
    open_st = request.args.get("open", type=int)
    return render_template("flat.html", f=f, c=c, st=st, cards=cards, pics=pics, hist=hist,
                           open_st=open_st, tab=request.args.get("tab", "stages"), nav="home")


def work_or_404(wid):
    w = db.q("SELECT * FROM works WHERE id=?", (wid,), one=True)
    if not w:
        abort(404)
    flat_or_404(w["flat_id"])
    return w


@app.route("/w/<int:wid>/<action>", methods=["POST"])
@login_required
def work_action(wid, action):
    w = work_or_404(wid)
    name, _, need = TPL[w["stage"]][1][w["idx"]]
    d = now()
    back = redirect(url_for("flat", fid=w["flat_id"], open=w["stage"]) + f"#s{w['stage']}")
    if action == "start" and can("pr") and w["status"] == "no":
        db.x("UPDATE works SET status='wk', date=? WHERE id=?", (d, wid))
        log(w["flat_id"], w["stage"], "b", f"{name}: работы начаты")
    elif action == "send" and can("pr") and w["status"] in ("no", "wk"):
        n = db.q("SELECT COUNT(*) AS n FROM photos WHERE work_id=?", (wid,), one=True)["n"]
        if n < need:
            flash(f"Нужно минимум {need} фото, загружено {n}")
            return back
        db.x("UPDATE works SET status='rv', date=?, ret='', sent_by=? WHERE id=?", (d, g.user["id"], wid))
        log(w["flat_id"], w["stage"], "b", f"{name}: " + (f"фотоотчёт сдан ({n} фото)" if need else "сдано на проверку"))
        flash("Отправлено на проверку ОКК")
    elif action == "accept" and can("okk") and w["status"] == "rv":
        db.x("UPDATE works SET status='ok', date=?, ret='' WHERE id=?", (d, wid))
        log(w["flat_id"], w["stage"], "g", f"{name}: принято ОКК")
        rest = db.q("SELECT status FROM works WHERE flat_id=? AND stage=?", (w["flat_id"], w["stage"]))
        flash("Этап принят: +5,56%" if all(r["status"] == "ok" for r in rest) else "Работа принята")
    elif action == "return" and can("okk") and w["status"] == "rv":
        reason = request.form.get("reason", "").strip()[:200] or "требуется доработка"
        db.x("UPDATE works SET status='wk', ret=? WHERE id=?", (reason, wid))
        if need:
            db.x("DELETE FROM photos WHERE work_id=?", (wid,))
        log(w["flat_id"], w["stage"], "r", f"{name}: возвращено — {reason}")
        flash("Возвращено прорабу")
    else:
        abort(403)
    db.commit()
    return back


@app.route("/w/<int:wid>/photo", methods=["POST"])
@login_required
def work_photo(wid):
    w = work_or_404(wid)
    if not can("pr") or w["status"] not in ("no", "wk"):
        abort(403)
    from PIL import Image, ImageOps
    added = 0
    for f in request.files.getlist("photos")[:10]:
        if not f or not f.filename:
            continue
        try:
            im = ImageOps.exif_transpose(Image.open(f.stream)).convert("RGB")
            im.thumbnail((1600, 1600))
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=80)
        except Exception:
            flash(f"Файл {f.filename} не похож на фото")
            continue
        db.x("INSERT INTO photos(work_id,data,mime,user_id,created) VALUES(?,?,?,?,?)",
             (wid, db.blob(buf.getvalue()), "image/jpeg", g.user["id"], now()))
        added += 1
    if added and w["status"] == "no":
        db.x("UPDATE works SET status='wk', date=? WHERE id=?", (now(), wid))
    db.commit()
    if added:
        flash(f"Фото добавлено: {added}")
    return redirect(url_for("flat", fid=w["flat_id"], open=w["stage"]) + f"#s{w['stage']}")


@app.route("/photo/<int:pid>")
@login_required
def photo(pid):
    p = db.q("SELECT * FROM photos WHERE id=?", (pid,), one=True)
    if not p:
        abort(404)
    work_or_404(p["work_id"])
    data = p["data"]
    return send_file(io.BytesIO(bytes(data)), mimetype=p["mime"], max_age=86400)


@app.route("/photo/<int:pid>/delete", methods=["POST"])
@login_required
def photo_delete(pid):
    p = db.q("SELECT * FROM photos WHERE id=?", (pid,), one=True)
    if not p:
        abort(404)
    w = work_or_404(p["work_id"])
    if not can("pr") or w["status"] not in ("no", "wk"):
        abort(403)
    db.x("DELETE FROM photos WHERE id=?", (pid,))
    db.commit()
    return redirect(url_for("flat", fid=w["flat_id"], open=w["stage"]) + f"#s{w['stage']}")


# ---------- этапы (сводка), задачи, уведомления ----------
@app.route("/stages")
@login_required
def stages():
    ids = complex_ids()
    cs = db.q(f"SELECT * FROM complexes WHERE id IN {in_list(ids)} ORDER BY id")
    cid = request.args.get("c", type=int) or (cs[0]["id"] if cs else None)
    rows, flats_l = [], []
    if cid:
        check_complex(cid)
        flats_l, _ = complex_stats(cid)
        n = len(flats_l) or 1
        for i in range(N):
            o = sum(1 for f in flats_l if f["states"][i] == "ok")
            p = sum(1 for f in flats_l if f["sent"][i])
            rows.append({"i": i, "o": o, "p": p, "okk": o * 100 / n, "pr": p * 100 / n})
    return render_template("stages.html", cs=cs, cid=cid, rows=rows, flats=flats_l, tasks=task_works(),
                           open_st=request.args.get("s", type=int), nav="stages")


@app.route("/tasks")
@login_required
def tasks():
    return redirect(url_for("stages") + "#tasks")


@app.route("/notifications")
@login_required
def notifications():
    ids = complex_ids()
    evs = db.q("SELECT e.*, f.number, c.name AS cname, u.name AS uname FROM events e JOIN flats f ON f.id=e.flat_id "
               f"JOIN complexes c ON c.id=f.complex_id LEFT JOIN users u ON u.id=e.user_id WHERE f.complex_id IN {in_list(ids)} "
               "ORDER BY e.id DESC LIMIT 100")
    seen = g.user["notes_seen"] or ""
    db.x("UPDATE users SET notes_seen=? WHERE id=?", (now(), g.user["id"]))
    db.commit()
    return render_template("notifications.html", evs=evs, seen=seen, nav="home")


# ---------- профиль ----------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        old, new = request.form.get("old", ""), request.form.get("new", "")
        if not check_password_hash(g.user["pw"], old):
            flash("Текущий пароль неверный")
        elif len(new) < 6:
            flash("Новый пароль — минимум 6 символов")
        else:
            db.x("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(new), g.user["id"]))
            db.commit()
            flash("Пароль изменён")
        return redirect(url_for("profile"))
    n_c = len(complex_ids())
    return render_template("profile.html", n_c=n_c, nav="profile")


# ---------- администрирование ----------
@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        uid = request.form.get("uid", type=int)
        u = db.q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if not u or u["id"] == g.user["id"] and request.form.get("act") in ("block", "save", "approve"):
            flash("Свою учётную запись так менять нельзя")
            return redirect(url_for("admin_users"))
        act = request.form.get("act")
        if act in ("approve", "save"):
            role = request.form.get("role", u["role"])
            if role not in ROLES:
                abort(400)
            db.x("UPDATE users SET role=?, status='active' WHERE id=?", (role, uid))
            db.x("DELETE FROM access WHERE user_id=?", (uid,))
            for cid in request.form.getlist("cx", type=int):
                db.x("INSERT INTO access(user_id, complex_id) VALUES(?,?)", (uid, cid))
            flash(f"{u['name']}: доступ сохранён")
        elif act == "block":
            db.x("UPDATE users SET status='blocked' WHERE id=?", (uid,))
            flash(f"{u['name']}: заблокирован")
        elif act == "unblock":
            db.x("UPDATE users SET status='active' WHERE id=?", (uid,))
        elif act == "reset":
            tmp = f"{secrets.randbelow(900000) + 100000}"
            db.x("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(tmp), uid))
            flash(f"{u['name']}: временный пароль {tmp} — передайте сотруднику")
        db.commit()
        return redirect(url_for("admin_users"))
    users = db.q("SELECT * FROM users ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, id DESC")
    acc = {}
    for a in db.q("SELECT * FROM access"):
        acc.setdefault(a["user_id"], set()).add(a["complex_id"])
    cs = db.q("SELECT * FROM complexes ORDER BY id")
    return render_template("admin_users.html", users=users, acc=acc, cs=cs, nav="profile")


def parse_numbers(spec):
    out = []
    for part in re.split(r"[,\s;]+", spec or ""):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if 0 < b - a < 1000:
                out += [str(i) for i in range(a, b + 1)]
        else:
            out.append(part[:12])
    seen, res = set(), []
    for n in out:
        if n not in seen:
            seen.add(n)
            res.append(n)
    return res[:1000]


def add_flats(cid, numbers, kind):
    for n in numbers:
        fid = db.x("INSERT INTO flats(complex_id, number, kind) VALUES(?,?,?)", (cid, n, kind), returning=True)
        for si, (_, works, _) in enumerate(TPL):
            for wi in range(len(works)):
                db.x("INSERT INTO works(flat_id, stage, idx) VALUES(?,?,?)", (fid, si, wi))


@app.route("/admin/objects", methods=["GET", "POST"])
@admin_required
def admin_objects():
    if request.method == "POST":
        act = request.form.get("act")
        if act == "create":
            name = request.form.get("name", "").strip()[:120]
            nums = parse_numbers(request.form.get("numbers"))
            if not name or not nums:
                flash("Укажите название ЖК и номера квартир, например 1-42 или 187, 193, 199")
                return redirect(url_for("admin_objects"))
            cid = db.x("INSERT INTO complexes(name, sub, city, created) VALUES(?,?,?,?)",
                       (name, request.form.get("sub", "").strip()[:60], request.form.get("city", "Алматы").strip()[:60] or "Алматы", now()),
                       returning=True)
            add_flats(cid, nums, request.form.get("kind", "типовой"))
            flash(f"Создан ЖК «{name}»: {len(nums)} кв.")
        elif act == "add":
            cid = request.form.get("cid", type=int)
            nums = parse_numbers(request.form.get("numbers"))
            exist = {r["number"] for r in db.q("SELECT number FROM flats WHERE complex_id=?", (cid,))}
            nums = [n for n in nums if n not in exist]
            add_flats(cid, nums, request.form.get("kind", "типовой"))
            flash(f"Добавлено квартир: {len(nums)}")
        elif act == "delete":
            cid = request.form.get("cid", type=int)
            db.x("DELETE FROM complexes WHERE id=?", (cid,))
            flash("ЖК удалён")
        db.commit()
        return redirect(url_for("admin_objects"))
    cs = db.q("SELECT c.*, (SELECT COUNT(*) FROM flats f WHERE f.complex_id=c.id) AS n FROM complexes c ORDER BY c.id")
    return render_template("admin_objects.html", cs=cs, nav="profile")


@app.route("/sw.js")
def sw():
    return app.send_static_file("sw.js"), 200, {"Content-Type": "application/javascript", "Service-Worker-Allowed": "/"}


@app.errorhandler(403)
def e403(_e):
    return render_template("error.html", msg="Это действие недоступно для вашей роли"), 403


@app.errorhandler(404)
def e404(_e):
    return render_template("error.html", msg="Страница не найдена или нет доступа"), 404


if __name__ == "__main__":
    app.run(debug=True)
