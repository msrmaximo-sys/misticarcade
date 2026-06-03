# ============================================================
#  MisticArcade Hub v2.0 — Servidor Flask
#  Archivo: app.py  (raíz del proyecto)
#
#  Características:
#    - SQLite con tabla usuarios (saldo_virtual) y sahumerios (stock)
#    - Sesiones Flask para login ligero
#    - Sistema de recompensa/castigo vinculado al juego
#    - Compra real con verificación de saldo y stock
#    - Anti-SQLi: parámetros enlazados siempre
#    - Anti-XSS: html.escape en todas las entradas de texto
# ============================================================

import sqlite3
import hashlib
import hmac
import os
import re
import html
from flask import (Flask, render_template, request,
                   jsonify, session, g)

app = Flask(__name__)

# ── Claves de seguridad ───────────────────────────────────────────────────
# En producción usa variables de entorno. Ejemplo Render/PythonAnywhere:
#   export SECRET_KEY="tu_clave_larga_aleatoria"
app.secret_key  = os.environ.get("SECRET_KEY",  "mistic_secret_K9#mP2_cambia_en_prod")
SCORE_SECRET    = os.environ.get("SCORE_SECRET", "s3cr3t_sc0r3_k3y_!Z7")

DATABASE = os.environ.get("DATABASE_PATH", "sahumar.db")

# Saldo inicial para usuarios nuevos (suficiente para al menos un sahumerio)
SALDO_INICIAL = 2000.0


# ════════════════════════════════════════════
#  BASE DE DATOS
# ════════════════════════════════════════════

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Crea tablas e inserta datos de ejemplo si no existen."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre          TEXT    NOT NULL UNIQUE,
            saldo_virtual   REAL    NOT NULL DEFAULT 2000.0
        );

        CREATE TABLE IF NOT EXISTS sahumerios (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre  TEXT    NOT NULL,
            precio  REAL    NOT NULL,
            stock   INTEGER NOT NULL DEFAULT 10,
            desc    TEXT,
            emoji   TEXT
        );

        CREATE TABLE IF NOT EXISTS coupons (
            code        TEXT    PRIMARY KEY,
            discount    REAL    NOT NULL,
            session_id  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );
    """)

    if db.execute("SELECT COUNT(*) FROM sahumerios").fetchone()[0] == 0:
        sahumerios = [
            ("Sahumerio Nag Champa",      350.0, 15, "El clásico indio. Floral, cálido y meditativo.",          "🌸"),
            ("Sahumerio Sándalo",          280.0, 20, "Madera sagrada. Purifica y centra la mente.",             "🪵"),
            ("Sahumerio Copal Blanco",     320.0, 12, "Resina ancestral mesoamericana. Limpia el espacio.",     "🌿"),
            ("Sahumerio Rosa y Mirra",     390.0,  8, "Combinación romántica y protectora.",                    "🌹"),
            ("Sahumerio Dragón de Sangre", 450.0,  5, "Poderosa resina rojiza. Energía y protección máxima.",  "🔴"),
            ("Sahumerio Jazmín",           260.0, 18, "Floral intenso. Eleva el humor y atrae abundancia.",    "✨"),
        ]
        db.executemany(
            "INSERT INTO sahumerios (nombre, precio, stock, desc, emoji) VALUES (?,?,?,?,?)",
            sahumerios
        )
    db.commit()


# ════════════════════════════════════════════
#  SANITIZACIÓN  (anti-XSS)
# ════════════════════════════════════════════

def s(text, max_len=200):
    """Escapa HTML y limita longitud. Usar en TODA entrada de usuario."""
    if not isinstance(text, str):
        return ""
    return html.escape(text.strip())[:max_len]


# ════════════════════════════════════════════
#  AUTENTICACIÓN (login simple sin contraseña —
#  adecuado para laboratorio/demo; agregar bcrypt
#  para producción real)
# ════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def login():
    data   = request.get_json(silent=True) or {}
    nombre = s(data.get("nombre", ""), 50)

    if not nombre or len(nombre) < 2:
        return jsonify({"ok": False, "error": "Nombre inválido (mín. 2 caracteres)"}), 400

    db  = get_db()
    row = db.execute("SELECT * FROM usuarios WHERE nombre=?", (nombre,)).fetchone()

    if not row:
        # Crear usuario nuevo con saldo inicial
        db.execute(
            "INSERT INTO usuarios (nombre, saldo_virtual) VALUES (?,?)",
            (nombre, SALDO_INICIAL)
        )
        db.commit()
        row = db.execute("SELECT * FROM usuarios WHERE nombre=?", (nombre,)).fetchone()

    session["user_id"]   = row["id"]
    session["user_name"] = row["nombre"]
    return jsonify({
        "ok":    True,
        "nombre": row["nombre"],
        "saldo":  row["saldo_virtual"]
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"logged": False}), 401
    db  = get_db()
    row = db.execute("SELECT nombre, saldo_virtual FROM usuarios WHERE id=?", (uid,)).fetchone()
    if not row:
        session.clear()
        return jsonify({"logged": False}), 401
    return jsonify({"logged": True, "nombre": row["nombre"], "saldo": row["saldo_virtual"]})


def require_login():
    """Devuelve None si OK, o una respuesta de error si no hay sesión."""
    if not session.get("user_id"):
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    return None


# ════════════════════════════════════════════
#  CATÁLOGO
# ════════════════════════════════════════════

@app.route("/")
def index():
    with app.app_context():
        init_db()
    return render_template("index.html")


@app.route("/api/products")
def api_products():
    q  = s(request.args.get("q", ""))
    db = get_db()
    if q:
        rows = db.execute(
            "SELECT * FROM sahumerios WHERE nombre LIKE ? OR desc LIKE ?",
            (f"%{q}%", f"%{q}%")
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM sahumerios").fetchall()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════
#  SISTEMA DE RECOMPENSA / CASTIGO DEL JUEGO
# ════════════════════════════════════════════

@app.route("/api/game-token")
def game_token():
    err = require_login()
    if err: return err
    token = os.urandom(16).hex()
    session["game_token"]  = token
    session["reward_sent"] = False
    session["penalty_sent"] = False
    return jsonify({"token": token})


@app.route("/api/reward", methods=["POST"])
def reward():
    """
    Llama el cliente cuando el usuario supera 500 puntos.
    Suma $500 al saldo. Verificado con firma HMAC.
    """
    err = require_login()
    if err: return err

    data      = request.get_json(silent=True) or {}
    score     = data.get("score")
    signature = data.get("signature", "")
    token     = session.get("game_token", "")

    if not isinstance(score, int) or score < 0 or score > 999999:
        return jsonify({"ok": False, "error": "Puntaje inválido"}), 400
    if not token:
        return jsonify({"ok": False, "error": "Sin token de partida"}), 403

    # Verificar firma HMAC
    expected = hmac.new(
        SCORE_SECRET.encode(),
        f"{token}:{score}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"ok": False, "error": "Firma inválida"}), 403

    if score < 500:
        return jsonify({"ok": False, "error": "Puntaje insuficiente para recompensa"}), 200

    if session.get("reward_sent"):
        db  = get_db()
        row = db.execute("SELECT saldo_virtual FROM usuarios WHERE id=?",
                         (session["user_id"],)).fetchone()
        return jsonify({"ok": True, "repeated": True, "saldo": row["saldo_virtual"]})

    db = get_db()
    db.execute(
        "UPDATE usuarios SET saldo_virtual = saldo_virtual + 500 WHERE id=?",
        (session["user_id"],)
    )
    db.commit()
    session["reward_sent"] = True

    row = db.execute("SELECT saldo_virtual FROM usuarios WHERE id=?",
                     (session["user_id"],)).fetchone()
    return jsonify({"ok": True, "ganado": 500, "saldo": row["saldo_virtual"]})


@app.route("/api/penalty", methods=["POST"])
def penalty():
    """
    Llama el cliente cuando el juego termina con puntaje < 100.
    Resta $200 del saldo (mínimo 0).
    """
    err = require_login()
    if err: return err

    data  = request.get_json(silent=True) or {}
    score = data.get("score")
    token = session.get("game_token", "")
    signature = data.get("signature", "")

    if not isinstance(score, int) or score < 0:
        return jsonify({"ok": False, "error": "Puntaje inválido"}), 400
    if not token:
        return jsonify({"ok": False, "error": "Sin token de partida"}), 403

    expected = hmac.new(
        SCORE_SECRET.encode(),
        f"{token}:{score}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"ok": False, "error": "Firma inválida"}), 403

    if score >= 100:
        return jsonify({"ok": False, "error": "Puntaje >= 100, no hay penalización"})

    if session.get("penalty_sent"):
        db  = get_db()
        row = db.execute("SELECT saldo_virtual FROM usuarios WHERE id=?",
                         (session["user_id"],)).fetchone()
        return jsonify({"ok": True, "repeated": True, "saldo": row["saldo_virtual"]})

    db = get_db()
    db.execute(
        "UPDATE usuarios SET saldo_virtual = MAX(0, saldo_virtual - 200) WHERE id=?",
        (session["user_id"],)
    )
    db.commit()
    session["penalty_sent"] = True

    row = db.execute("SELECT saldo_virtual FROM usuarios WHERE id=?",
                     (session["user_id"],)).fetchone()
    return jsonify({"ok": True, "perdido": 200, "saldo": row["saldo_virtual"]})


# ════════════════════════════════════════════
#  COMPRA CON STOCK Y SALDO REAL
# ════════════════════════════════════════════

@app.route("/api/checkout", methods=["POST"])
def checkout():
    err = require_login()
    if err: return err

    data   = request.get_json(silent=True) or {}
    cart   = data.get("cart", [])   # [{ id, qty }, ...]
    coupon = s(data.get("coupon", ""), 20)

    if not cart:
        return jsonify({"ok": False, "error": "El carrito está vacío"}), 400

    db  = get_db()
    uid = session["user_id"]

    # ── Calcular total y verificar stock ──────────────────────────────────
    total = 0.0
    items = []
    for item in cart:
        pid = item.get("id")
        qty = item.get("qty", 1)

        if not isinstance(pid, int) or not isinstance(qty, int) or qty < 1:
            return jsonify({"ok": False, "error": "Datos de carrito inválidos"}), 400

        row = db.execute(
            "SELECT id, nombre, precio, stock FROM sahumerios WHERE id=?", (pid,)
        ).fetchone()

        if not row:
            return jsonify({"ok": False, "error": f"Producto #{pid} no encontrado"}), 404
        if row["stock"] < qty:
            return jsonify({
                "ok": False,
                "error": f"Stock insuficiente para '{row['nombre']}'. Disponible: {row['stock']}"
            })

        total += row["precio"] * qty
        items.append({"id": pid, "qty": qty, "precio": row["precio"], "nombre": row["nombre"]})

    # ── Validar cupón (opcional) ──────────────────────────────────────────
    discount_pct = 0.0
    if coupon and re.match(r'^MISTIC-[0-9A-F]{6}$', coupon):
        crow = db.execute(
            "SELECT discount FROM coupons WHERE code=? AND used=0", (coupon,)
        ).fetchone()
        if crow:
            discount_pct = crow["discount"]

    descuento = round(total * discount_pct, 2)
    total_final = round(total - descuento, 2)

    # ── Verificar saldo del usuario ───────────────────────────────────────
    urow = db.execute("SELECT saldo_virtual FROM usuarios WHERE id=?", (uid,)).fetchone()
    if urow["saldo_virtual"] < total_final:
        return jsonify({
            "ok": False,
            "error": (
                f"Saldo insuficiente. Necesitás ${total_final:.2f} "
                f"y tenés ${urow['saldo_virtual']:.2f}. "
                f"¡Jugá Space Invaders para ganar más saldo!"
            )
        })

    # ── Aplicar transacción ───────────────────────────────────────────────
    db.execute(
        "UPDATE usuarios SET saldo_virtual = saldo_virtual - ? WHERE id=?",
        (total_final, uid)
    )
    for it in items:
        db.execute(
            "UPDATE sahumerios SET stock = stock - ? WHERE id=?",
            (it["qty"], it["id"])
        )
    if coupon and discount_pct:
        db.execute("UPDATE coupons SET used=1 WHERE code=?", (coupon,))

    db.commit()

    nuevo_saldo = db.execute(
        "SELECT saldo_virtual FROM usuarios WHERE id=?", (uid,)
    ).fetchone()["saldo_virtual"]

    return jsonify({
        "ok":          True,
        "subtotal":    total,
        "descuento":   descuento,
        "total_final": total_final,
        "nuevo_saldo": nuevo_saldo,
        "mensaje":     f"¡Compra exitosa! Gastaste ${total_final:.2f}. Saldo restante: ${nuevo_saldo:.2f}"
    })


# ════════════════════════════════════════════
#  CUPÓN (sistema legacy del v1, mantenido)
# ════════════════════════════════════════════

@app.route("/api/apply-coupon", methods=["POST"])
def apply_coupon():
    data = request.get_json(silent=True) or {}
    code = s(data.get("code", ""), 20)
    if not re.match(r'^MISTIC-[0-9A-F]{6}$', code):
        return jsonify({"valid": False, "error": "Formato de cupón inválido"}), 400
    db  = get_db()
    row = db.execute(
        "SELECT * FROM coupons WHERE code=? AND used=0", (code,)
    ).fetchone()
    if not row:
        return jsonify({"valid": False, "error": "Cupón no encontrado o ya usado"})
    return jsonify({"valid": True, "discount": int(row["discount"] * 100)})


# ════════════════════════════════════════════
if __name__ == "__main__":
    import os
    with app.app_context():
        init_db()  # 🌟 Mantenemos esto para que cree la base de datos sola
        
    # Detectamos el puerto que nos da Render, si no encuentra ninguno usa el 5000
    port = int(os.environ.get("PORT", 5000))
    
    # 🌟 Apagamos el debug para producción y usamos el puerto dinámico
    app.run(debug=False, host="0.0.0.0", port=port)