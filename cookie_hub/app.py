"""Private vault for sessions belonging to one account. No server-side scraping."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from flask import Flask, abort, jsonify, redirect, render_template, request, session
from sqlalchemy import Boolean, Column, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool
from werkzeug.exceptions import HTTPException


class Base(DeclarativeBase):
    pass


class HubState(Base):
    __tablename__ = "hub_state"
    id = Column(Integer, primary_key=True)
    owner_uid = Column(String(40), nullable=True)
    blocked = Column(Boolean, nullable=False, default=False)
    reason = Column(String(80), nullable=False, default="")


class Credential(Base):
    __tablename__ = "vault_sessions"
    id = Column(String(36), primary_key=True)
    label = Column(String(80), nullable=False)
    owner_uid = Column(String(40), nullable=False)
    sealed = Column(Text, nullable=False)
    created_at = Column(Integer, nullable=False)


def parse_cookie(value):
    result = {}
    for item in value.split(";"):
        if "=" in item:
            key, val = item.strip().split("=", 1)
            result[key.strip()] = val.strip()
    return result


def create_app(config=None):
    app = Flask(__name__, template_folder="templates")
    app.config.update(
        DATABASE_URL=os.environ.get("DATABASE_URL", ""),
        HUB_ADMIN_TOKEN=os.environ.get("HUB_ADMIN_TOKEN", ""),
        HUB_CLIENT_TOKEN=os.environ.get("HUB_CLIENT_TOKEN", ""),
        ENCRYPTION_SECRET=os.environ.get("ENCRYPTION_SECRET", ""),
        MAX_CONTENT_LENGTH=65536,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )
    if config:
        app.config.update(config)
    for key in ("HUB_ADMIN_TOKEN", "HUB_CLIENT_TOKEN", "ENCRYPTION_SECRET"):
        if len(app.config[key]) < 32:
            raise RuntimeError(f"Set {key} to a secret of at least 32 characters")
    if app.config["HUB_ADMIN_TOKEN"] == app.config["HUB_CLIENT_TOKEN"]:
        raise RuntimeError("Admin and client tokens must differ")
    url = app.config["DATABASE_URL"]
    if not url:
        raise RuntimeError("DATABASE_URL is required")
    if url.startswith(("postgres://", "postgresql://")):
        url = "postgresql+psycopg://" + url.split("://", 1)[1]
    engine_options = {"pool_pre_ping": True, "hide_parameters": True}
    if url == "sqlite://":
        engine_options.update(
            poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
    engine = create_engine(url, **engine_options)
    factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with factory.begin() as db:
        if db.get(HubState, 1) is None:
            db.add(HubState(id=1, blocked=False, reason=""))
    cipher = Fernet(base64.urlsafe_b64encode(
        hashlib.sha256(app.config["ENCRYPTION_SECRET"].encode()).digest()
    ))
    app.secret_key = hashlib.sha256(
        ("browser-session:" + app.config["ENCRYPTION_SECRET"]).encode()
    ).digest()
    app.extensions.update(vault_db=factory, vault_engine=engine)
    failures, throttle_lock = defaultdict(deque), threading.Lock()

    def token_matches(value, key):
        return hmac.compare_digest(value.encode(), app.config[key].encode())

    def api_role():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        value = header[7:]
        if token_matches(value, "HUB_ADMIN_TOKEN"):
            return "admin"
        if token_matches(value, "HUB_CLIENT_TOKEN"):
            return "client"
        return None

    def authenticated(admin=False):
        role = api_role() if request.path.startswith("/api/") else (
            "admin" if session.get("admin") else None
        )
        if role is None:
            abort(401)
        if admin and role != "admin":
            abort(403)

    def csrf_check():
        supplied = request.form.get("csrf", "")
        if not supplied or not hmac.compare_digest(
            supplied, session.get("csrf", "")
        ):
            abort(403)

    def state_dict(state):
        return {"owner_uid": state.owner_uid, "blocked": state.blocked,
                "reason": state.reason}

    def add_credentials(items):
        if not isinstance(items, list) or not 1 <= len(items) <= 100:
            abort(400, "Supply between 1 and 100 sessions")
        parsed = []
        for item in items:
            if not isinstance(item, dict):
                abort(400, "Invalid session")
            cookie, token = item.get("cookie", ""), item.get("access_token", "")
            label = item.get("label", "Session")
            if not all(isinstance(v, str) for v in (cookie, token, label)):
                abort(400, "Invalid session fields")
            values = parse_cookie(cookie)
            uid = values.get("c_user", "")
            if not uid.isascii() or not uid.isdigit() or not values.get("xs"):
                abort(400, "Cookie requires numeric c_user and xs")
            if len(cookie) > 16384 or len(token) > 8192 or len(label) > 80:
                abort(400, "Session field too large")
            parsed.append((uid, cookie, token, label.strip() or "Session"))
        ids = []
        with factory.begin() as db:
            state = db.execute(select(HubState).where(
                HubState.id == 1
            ).with_for_update()).scalar_one()
            owner = state.owner_uid or parsed[0][0]
            if any(item[0] != owner for item in parsed):
                abort(409, "This hub stores sessions for one account only")
            state.owner_uid = owner
            for uid, cookie, token, label in parsed:
                sid = str(uuid.uuid4())
                sealed = cipher.encrypt(json.dumps({
                    "cookie": cookie, "access_token": token
                }).encode()).decode()
                db.add(Credential(id=sid, label=label, owner_uid=uid,
                                  sealed=sealed, created_at=int(time.time())))
                ids.append(sid)
        return ids

    @app.after_request
    def headers(response):
        response.headers.update({
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy":
                "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        })
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        # Do not serialize request bodies or submitted credential values.
        detail = exc.description if exc.code in (400, 409, 423) else exc.name
        return jsonify(error=detail), exc.code

    @app.errorhandler(Exception)
    def server_error(exc):
        # Do not log SQL connection strings, ciphertext or request values.
        return jsonify(error="Internal server error"), 500

    @app.get("/healthz")
    def health():
        with factory() as db:
            db.execute(select(HubState.id).limit(1)).all()
        return jsonify(ok=True)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        message = ""
        if request.method == "POST":
            csrf_check()
            address = request.remote_addr or "unknown"
            now = time.monotonic()
            with throttle_lock:
                # Bound memory and expire failed-attempt windows.
                for key in list(failures):
                    while failures[key] and failures[key][0] < now - 300:
                        failures[key].popleft()
                    if not failures[key]:
                        del failures[key]
                if len(failures) >= 10000:
                    abort(429)
                if len(failures.get(address, ())) >= 10:
                    abort(429)
            if token_matches(request.form.get("token", ""), "HUB_ADMIN_TOKEN"):
                session.clear()
                session.update(admin=True, csrf=secrets.token_urlsafe(32))
                session.permanent = True
                return redirect("/")
            with throttle_lock:
                failures[address].append(now)
            message = "Login failed"
        if not session.get("admin"):
            return render_template("index.html", logged_in=False,
                                   message=message, csrf=session["csrf"])
        with factory() as db:
            state = state_dict(db.get(HubState, 1))
            records = db.execute(select(Credential).order_by(
                Credential.created_at, Credential.id
            )).scalars().all()
        return render_template("index.html", logged_in=True, state=state,
                               records=records, csrf=session["csrf"])

    @app.post("/sessions/add")
    def form_add():
        authenticated(admin=True)
        csrf_check()
        if request.form.get("owned") != "yes":
            abort(400, "Confirm these are your own account sessions")
        lines = [line.strip() for line in request.form.get("cookies", "").splitlines()
                 if line.strip()]
        label = request.form.get("label", "Session").strip()
        token = request.form.get("access_token", "").strip()
        add_credentials([{"label": f"{label} {i + 1}", "cookie": line,
                          "access_token": token} for i, line in enumerate(lines)])
        return redirect("/")

    @app.post("/sessions/<sid>/delete")
    def form_delete(sid):
        authenticated(admin=True)
        csrf_check()
        with factory.begin() as db:
            record = db.get(Credential, sid)
            if record is not None:
                db.delete(record)
        return redirect("/")

    @app.post("/resume")
    def form_resume():
        authenticated(admin=True)
        csrf_check()
        if request.form.get("reviewed") != "yes":
            abort(400, "Confirm the provider restriction has been resolved")
        with factory.begin() as db:
            state = db.execute(select(HubState).where(
                HubState.id == 1
            ).with_for_update()).scalar_one()
            state.blocked, state.reason = False, ""
        return redirect("/")

    @app.post("/logout")
    def form_logout():
        csrf_check()
        session.clear()
        return redirect("/")

    @app.get("/api/state")
    def api_state():
        authenticated()
        with factory() as db:
            return jsonify(state_dict(db.get(HubState, 1)))

    @app.get("/api/sessions")
    def api_list():
        authenticated()
        with factory() as db:
            records = db.execute(select(Credential).order_by(
                Credential.created_at, Credential.id
            )).scalars().all()
            return jsonify(sessions=[{
                "id": row.id, "label": row.label, "owner_uid": row.owner_uid,
                "created_at": row.created_at
            } for row in records])

    @app.post("/api/sessions")
    def api_add():
        authenticated(admin=True)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or payload.get("owned") is not True:
            abort(400, "Confirm ownership")
        return jsonify(ids=add_credentials(payload.get("sessions"))), 201

    @app.post("/api/sessions/<sid>/checkout")
    def checkout(sid):
        authenticated()
        with factory.begin() as db:
            state = db.execute(select(HubState).where(
                HubState.id == 1
            ).with_for_update()).scalar_one()
            if state.blocked:
                abort(423, "Hub paused by a provider restriction")
            row = db.get(Credential, sid)
            if row is None:
                abort(404)
            values = json.loads(cipher.decrypt(row.sealed.encode()))
            return jsonify(id=row.id, owner_uid=row.owner_uid, **values)

    @app.post("/api/halt")
    def halt():
        authenticated()
        payload = request.get_json(silent=True)
        code = payload.get("code") if isinstance(payload, dict) else None
        if code not in (368, 4, 17, 32, 613, 429):
            abort(400, "Unsupported stop reason")
        with factory.begin() as db:
            state = db.execute(select(HubState).where(
                HubState.id == 1
            ).with_for_update()).scalar_one()
            state.blocked = True
            state.reason = f"Provider restriction {code}"
        return jsonify(blocked=True)

    return app
