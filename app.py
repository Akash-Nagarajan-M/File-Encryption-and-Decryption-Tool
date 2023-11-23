from flask import Flask, request, render_template, redirect, session, send_file, url_for
from flask_sqlalchemy import SQLAlchemy
from file_encr import process_file
from keygen import generate_diffie_hellman_key_pair
import bcrypt
import os

os.makedirs("temp_uploads", exist_ok=True)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)
app.secret_key = "secret_key"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # handle request
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        new_user = User(
            name=name,
            email=email,
            password=password,
        )
        db.session.add(new_user)
        db.session.commit()
        generate_diffie_hellman_key_pair(name)
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["email"] = user.email
            session["username"] = user.name
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid user")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "email" in session:
        return render_template("dashboard.html")

    return redirect("/login")


@app.route("/process", methods=["POST"])
def process():
    mode = request.form["mode"]
    print(mode)
    receiver_name = request.form["receiver"]
    print(receiver_name)
    file = request.files["file"]

    # Save the uploaded file to a temporary location
    temp_file_path = os.path.join("temp_uploads", file.filename)
    file.save(temp_file_path)
    sender_name = session["username"]
    print(sender_name)
    processed_file_path = process_file(temp_file_path, sender_name, receiver_name, mode)
    print(processed_file_path)
    # if not processed_file_path or isinstance(processed_file_path, str):
    #     return render_template("result.html", result_message=processed_file_path)

    return render_template("result.html", result_file=processed_file_path)


@app.template_filter("basename")
def basename(value):
    return os.path.basename(value)


@app.route("/download/<filename>")
def download_file(filename):
    directory = "temp_uploads"
    file_path = os.path.join(directory, filename)
    print("Download file:", file_path)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return render_template("result.html", result_message="File not found.")


@app.route("/logout")
def logout():
    session.pop("email", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(host='0.0.0.0',port=3000)
