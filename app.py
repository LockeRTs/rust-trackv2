import os, re, time
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///rust_track.db").replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Сначала войди в аккаунт."

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(24), nullable=False)
    username_key = db.Column(db.String(24), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    ban_reason = db.Column(db.String(250), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class WatchedPlayer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    steamid = db.Column(db.String(17), nullable=False)
    display_name = db.Column(db.String(100), nullable=False, default="Steam игрок")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "steamid", name="uq_user_watched_steamid"),)


class RegisterForm(FlaskForm):
    username = StringField("Никнейм", validators=[
        DataRequired(), Length(min=3, max=24),
        Regexp(r"^[A-Za-zА-Яа-яЁё0-9_]+$", message="Используй буквы, цифры и подчёркивание.")
    ])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Повтори пароль", validators=[DataRequired(), EqualTo("password", message="Пароли не совпадают.")])
    submit = SubmitField("Создать аккаунт")

class LoginForm(FlaskForm):
    username = StringField("Никнейм", validators=[DataRequired(), Length(max=24)])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.before_request
def enforce_account_status():
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        flash("Этот аккаунт заблокирован. Если считаешь это ошибкой, обратись к администрации.", "error")
        return redirect(url_for("login"))

@app.context_processor
def inject_globals():
    return {"site_name": "Rust Track"}

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def init_admin():
    admin_name = os.environ.get("ADMIN_USERNAME", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if not admin_name or not admin_password:
        app.logger.warning("ADMIN_USERNAME/ADMIN_PASSWORD not set; admin account was not created.")
        return
    key = admin_name.casefold()
    existing = User.query.filter_by(username_key=key).first()
    if existing:
        existing.is_admin = True
        if os.environ.get("RESET_ADMIN_PASSWORD", "false").lower() == "true":
            existing.set_password(admin_password)
    else:
        u = User(username=admin_name, username_key=key, is_admin=True)
        u.set_password(admin_password)
        db.session.add(u)
    db.session.commit()

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.username.data.strip()
        key = name.casefold()
        if User.query.filter_by(username_key=key).first():
            flash("Такой никнейм уже занят. Выбери другой.", "error")
        else:
            user = User(username=name, username_key=key)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f"Аккаунт создан! Твой номер в системе: #{user.id}", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", form=form, mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username_key=form.username.data.strip().casefold()).first()
        if user and user.check_password(form.password.data):
            if user.is_banned:
                flash("Этот аккаунт заблокирован.", "error")
            else:
                login_user(user)
                return redirect(url_for("dashboard"))
        else:
            flash("Неверный никнейм или пароль.", "error")
    return render_template("auth.html", form=form, mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Ты вышел из аккаунта.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.get("/api/player/<path:query>")
@login_required
def player_api(query):
    key = os.environ.get("STEAM_API_KEY", "").strip()
    if not key:
        return jsonify({"error": "Администратор ещё не настроил Steam API Key."}), 503
    query = query.strip()
    try:
        steamid = resolve_steam_id(query, key)
        summaries = steam_get("/ISteamUser/GetPlayerSummaries/v2/", {"steamids": steamid}, key)
        players = summaries.get("response", {}).get("players", [])
        if not players:
            return jsonify({"error": "Профиль не найден или закрыт."}), 404
        player = players[0]
        owned = steam_get("/IPlayerService/GetOwnedGames/v1/", {
            "steamid": steamid, "include_appinfo": 1, "include_played_free_games": 1
        }, key).get("response", {})
        rust = next((g for g in owned.get("games", []) if g.get("appid") == 252490), None)
        hours = round(rust.get("playtime_forever", 0) / 60) if rust else None
        first_date = None
        try:
            ach = steam_get("/ISteamUserStats/GetPlayerAchievements/v1/",
                            {"steamid": steamid, "appid": 252490}, key)
            unlocked = [a.get("unlocktime", 0) for a in ach.get("playerstats", {}).get("achievements", [])
                        if a.get("achieved") == 1 and a.get("unlocktime", 0) > 0]
            if unlocked:
                first_date = time.strftime("%d.%m.%Y", time.localtime(min(unlocked)))
        except Exception:
            pass
        states = {0:"Не в сети",1:"В сети",2:"Занят",3:"Нет на месте",4:"Спит",5:"Ищет обмен",6:"Ищет игру"}
        status = states.get(int(player.get("personastate", 0)), "Статус неизвестен")
        if player.get("gameextrainfo"):
            status = "Играет: " + player["gameextrainfo"]
        return jsonify({
            "steamid": steamid, "name": player.get("personaname", "Steam игрок"),
            "profile": player.get("profileurl", ""), "status": status,
            "hours": hours, "first_date": first_date, "rust_found": rust is not None
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.RequestException:
        return jsonify({"error": "Steam временно не отвечает. Попробуй позже."}), 502
    except Exception:
        app.logger.exception("Steam lookup failed")
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500

@app.get("/api/watchlist")
@login_required
def get_watchlist():
    entries = WatchedPlayer.query.filter_by(user_id=current_user.id).order_by(WatchedPlayer.created_at.asc()).all()
    return jsonify([{"steamid": p.steamid, "name": p.display_name} for p in entries])

@app.post("/api/watchlist")
@login_required
def add_to_watchlist():
    data = request.get_json(silent=True) or {}
    steamid = str(data.get("steamid", "")).strip()
    name = str(data.get("name", "Steam игрок")).strip()[:100] or "Steam игрок"
    if not re.fullmatch(r"\d{17}", steamid):
        return jsonify({"error": "Некорректный SteamID64."}), 400
    existing = WatchedPlayer.query.filter_by(user_id=current_user.id, steamid=steamid).first()
    if existing:
        existing.display_name = name
    else:
        db.session.add(WatchedPlayer(user_id=current_user.id, steamid=steamid, display_name=name))
    db.session.commit()
    return jsonify({"ok": True})

@app.delete("/api/watchlist/<steamid>")
@login_required
def remove_from_watchlist(steamid):
    entry = WatchedPlayer.query.filter_by(user_id=current_user.id, steamid=steamid).first()
    if not entry:
        return jsonify({"error": "Игрок не найден в сохранённых."}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"ok": True})


def resolve_steam_id(value, key):
    if re.fullmatch(r"\d{17}", value):
        return value
    m = re.search(r"steamcommunity\.com/profiles/(\d{17})", value)
    if m:
        return m.group(1)
    m = re.search(r"steamcommunity\.com/id/([^/?#]+)", value)
    vanity = m.group(1) if m else value
    if not vanity or len(vanity) > 100 or any(c.isspace() for c in vanity):
        raise ValueError("Введи SteamID64 или ссылку на профиль Steam.")
    data = steam_get("/ISteamUser/ResolveVanityURL/v1/", {"vanityurl": vanity}, key)
    response = data.get("response", {})
    if response.get("success") != 1:
        raise ValueError("Не удалось найти Steam-профиль.")
    return response["steamid"]

def steam_get(path, params, key):
    p = dict(params)
    p["key"] = key
    response = requests.get("https://api.steampowered.com" + path, params=p, timeout=18)
    response.raise_for_status()
    return response.json()

@app.route("/developers")
def developers():
    return render_template("developers.html", developers=["Miurexz", "Locker", "Wate"])

@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin.html", users=users)

@app.post("/admin/ban/<int:user_id>")
@admin_required
def ban_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("Нельзя заблокировать собственный аккаунт.", "error")
    elif user.is_admin:
        flash("Нельзя заблокировать администратора через эту панель.", "error")
    else:
        user.is_banned = True
        user.ban_reason = (request.form.get("reason") or "Нарушение правил")[:250]
        db.session.commit()
        flash(f"Аккаунт #{user.id} ({user.username}) заблокирован.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/unban/<int:user_id>")
@admin_required
def unban_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()
    flash(f"Блокировка аккаунта #{user.id} снята.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(403)
def forbidden(_):
    return render_template("message.html", title="Нет доступа", message="Эта страница доступна только администратору."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("message.html", title="Не найдено", message="Такой страницы или аккаунта нет."), 404

with app.app_context():
    db.create_all()
    init_admin()

if __name__ == "__main__":
    app.run(debug=True)
