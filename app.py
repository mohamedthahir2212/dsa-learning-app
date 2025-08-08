"""
Flask web application with authentication and logging for learning DSA.

This app extends the basic DSA web app by adding user authentication,
administrative privileges, and a login/logout log for analytics.  Each
user must sign up and log in to access the lesson generator.  The admin
user (designated by the `is_admin` flag) has access to a logs page
showing all login and logout events.

Before running this app, install dependencies from requirements.txt and set
environment variables:

  * OPENAI_API_KEY – your OpenAI secret API key
  * FLASK_SECRET_KEY – a secret key for session management

To initialize the database and create an admin account, run:

    flask --app app.py shell
    >>> from app import db, User
    >>> db.create_all()
    >>> admin = User(username="your_admin_username", password=User.hash_password("password"), is_admin=True)
    >>> db.session.add(admin); db.session.commit()

Then start the app:

    flask --app app.py run

This will serve the app on localhost:5000.  For global hosting, deploy to
a platform like Render or Heroku, configure the environment variables, and
use a production WSGI server such as gunicorn.
"""

import os
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
import openai

app = Flask(__name__)

# Configuration
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dsa_app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Ensure OpenAI API key is set
openai.api_key = os.environ.get("OPENAI_API_KEY")
if not openai.api_key:
    raise RuntimeError(
        "OPENAI_API_KEY environment variable not set. Please set it before running the app."
    )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    @staticmethod
    def hash_password(password: str) -> str:
        return generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password, password)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # "login" or "logout"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref=db.backref("logs", lazy=True))


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


# Data for lesson generation
TOPICS = {
    "Arrays": "Arrays",
    "Linked Lists": "Linked Lists",
    "Stacks": "Stacks",
    "Queues": "Queues",
    "Trees": "Trees",
    "Graphs": "Graphs",
    "Sorting Algorithms": "Sorting Algorithms",
    "Searching Algorithms": "Searching Algorithms",
    "Hash Tables": "Hash Tables",
    "Dynamic Programming": "Dynamic Programming",
    "Recursion": "Recursion",
    "Algorithm Analysis (Big-O)": "Algorithm Analysis (Big-O)",
}

DIFFICULTIES = ["Beginner", "Intermediate", "Pro"]

SYSTEM_PROMPT = (
    "You are a patient and knowledgeable tutor who teaches Data Structures and Algorithms (DSA) "
    "to learners at various skill levels.  You provide clear explanations, illustrative examples, "
    "and Python code snippets where appropriate."
)


def generate_lesson(topic: str, difficulty: str) -> str:
    """Generate a lesson for the given topic and difficulty using OpenAI ChatCompletion."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Teach me about {topic} at a {difficulty} level. "
                "Explain the key concepts and provide Python code examples where relevant."
            ),
        },
    ]
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=messages,
            temperature=0.7,
        )
        return response.choices[0].message["content"]
    except Exception as exc:
        return f"Error contacting OpenAI API: {exc}"


@app.route("/")
@login_required
def index():
    return render_template("index.html", topics=TOPICS, difficulties=DIFFICULTIES)


@app.route("/generate", methods=["POST"])
@login_required
def generate():
    topic = request.form.get("topic")
    difficulty = request.form.get("difficulty")
    if topic not in TOPICS or difficulty not in DIFFICULTIES:
        flash("Invalid topic or difficulty selected.")
        return redirect(url_for("index"))
    lesson = generate_lesson(topic, difficulty)
    return render_template(
        "index.html",
        topics=TOPICS,
        difficulties=DIFFICULTIES,
        lesson=lesson,
        selected_topic=topic,
        selected_difficulty=difficulty,
    )

@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    """
    Simple chatbot interface.  Allows a logged in user to submit arbitrary
    questions about data structures and algorithms.  The assistant will
    respond with a concise explanation using the OpenAI API.

    The conversation is stateless: each question is handled independently
    without retaining history.  If the API call fails, an error message
    is displayed.
    """
    answer = None
    user_question = ""
    if request.method == "POST":
        user_question = request.form.get("question", "").strip()
        if user_question:
            try:
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_question},
                ]
                response = openai.ChatCompletion.create(
                    model="gpt-4o",
                    messages=messages,
                    temperature=0.7,
                )
                answer = response.choices[0].message["content"]
            except Exception as exc:
                answer = f"Error contacting OpenAI API: {exc}"
        else:
            flash("Please enter a question.")
    return render_template("chat.html", question=user_question, answer=answer)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            # Log the login event
            log = Log(user_id=user.id, event_type="login")
            db.session.add(log)
            db.session.commit()
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    # Log the logout event
    log = Log(user_id=current_user.id, event_type="logout")
    db.session.add(log)
    db.session.commit()
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Please provide both username and password.")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for("register"))
        new_user = User(
            username=username,
            password=User.hash_password(password),
            is_admin=False,
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/admin/logs")
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template("admin_logs.html", logs=logs)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)