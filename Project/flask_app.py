from flask import Flask, url_for, request, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from datetime import timedelta, datetime
import json
# import os

# These should be stored in a much more secure location, such as environment keys.
encryption_key = "TestKey"             # os.environ.get('key')
global_aes_key = b"8473384356565656"   # os.environ.get('aes')
global_hmac_key = b"7778934892347456"  # os.environ.get('hmac')

# The secret_key is what is used to encrypt the session cookie
app = Flask(__name__)
app.secret_key = encryption_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.permanent_session_lifetime = timedelta(seconds=1, days=5)

db = SQLAlchemy(app)

ADULT_TICKET_PRICE = 30
CHILD_TICKET_PRICE = 20
MAX_DAILY_ZOO_BOOKINGS = 5
MAX_DAILY_HOTEL_BOOKINGS = 10


class User(db.Model):
    email = db.Column(db.String(256))
    name = db.Column(db.String(256))
    password = db.Column(db.String(256))
    hashed_password = db.Column(db.String(256))
    hashed_email = db.Column(db.String(256), unique=True, primary_key=True)
    user_bookings = db.Column(db.String)
    loyalty_points = db.Column(db.Integer, default=0)

    def __init__(self, name, email, password, hashed_password, hashed_email, user_bookings, loyalty_points):
        self.name = name
        self.email = email
        self.password = password
        self.hashed_password = hashed_password
        self.hashed_email = hashed_email
        self.user_bookings = user_bookings
        self.loyalty_points = loyalty_points


class Bookings(db.Model):
    date = db.Column(db.String, primary_key=True, unique=True)
    hotel_bookings = db.Column(db.Integer)
    zoo_bookings = db.Column(db.Integer)

    def __init__(self, date, hotel_bookings, zoo_bookings):
        self.date = date
        self.hotel_bookings = hotel_bookings
        self.zoo_bookings = zoo_bookings


# Weird workaround to 16 byte requirement to aes key, but it works
# This is ok to do since we verify the password with a hashing encryption before decrypting anything
# This only works because the highest number this could go to is 7, since the password is required to be 8 chars
def get_aes_key_from_password(password):
    if len(password) > 16:
        return password[:16]
    else:
        aes_key = password
        count = 0
        while len(aes_key) < 16:
            aes_key += str(count)
            count += 1
        return aes_key


# It is probably best practice to move the encrypt and decrypt functions to a different python file and import it
# For now it stays here
def encrypt_string(string, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(string)

    hmac = HMAC.new(global_hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()
    encrypted_string = tag + cipher.nonce + ciphertext
    return encrypted_string


def decrypt_string(encrypted_string, aes_key):
    tag = encrypted_string[0:32]
    nonce = encrypted_string[32:40]
    ciphertext = encrypted_string[40:]

    try:
        hmac = HMAC.new(global_hmac_key, digestmod=SHA256)
        hmac.update(nonce + ciphertext).verify(tag)
    except ValueError:
        return False

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


def hash_encrypt_string(string):
    encrypted_string = SHA256.new()
    encrypted_string.update(bytes(string, 'utf-8'))
    return encrypted_string.hexdigest()


def check_signup_details(name, email, password, hashed_email):
    error_messages = []

    if "@" not in email:
        error_messages.insert(-1, "Please enter a valid email address.")
    if len(password) < 8:
        error_messages.insert(-1, "Your password must be at least 8 characters long.")
    if len(name) < 2:
        error_messages.insert(-1, "Please enter your full name.")
    if User.query.filter_by(hashed_email=hashed_email).count() > 0:
        # print(User.query.filter_by(hashed_email=hashed_email).count())
        error_messages.insert(-1, "Email already has an account registered.")

    return error_messages


def new_signup(name, email, password):
    aes_key = bytes(get_aes_key_from_password(password), "utf-8")
    # print(aes_key)
    encrypted_name = encrypt_string(name.encode("utf-8"), aes_key)
    encrypted_email = encrypt_string(email.encode("utf-8"), aes_key)

    # We use a constant key to encrypt the users password in the even the user forgets their password.
    # Doing this means their data can be recovered if their password needs to be changed.
    encrypted_password = encrypt_string(password.encode("utf-8"), global_aes_key)
    hashed_password = hash_encrypt_string(password)
    hashed_email = hash_encrypt_string(email)
    errors = check_signup_details(name, email, password, hashed_email)
    if len(errors) > 0:
        return errors
    else:
        new_user = User(encrypted_name, encrypted_email, encrypted_password, hashed_password, hashed_email, "{}", 0)
        db.session.add(new_user)
        db.session.commit()
        return []


def reformat_date(date_string):
    split = date_string.split("-")
    return split[2] + "-" + split[1] + "-" + split[0]


def check_booking_details(form):
    errors = []
    if "Hotel" not in form and "Zoo" not in form:
        errors.insert(-1, "Please pick a booking type.")

    user = User.query.filter_by(email=session["location"]).first()
    user_booking_data = json.loads(user.user_bookings)
    formatted_date = reformat_date(form["date"])
    date_details = Bookings.query.filter_by(date=formatted_date)

    if formatted_date in user_booking_data:
        errors.insert(-1, "You already have an active booking for this date!")

    if date_details.count() > 0:
        date_details = date_details.first()
        # (date_details)
        if "Hotel" in form:
            if date_details.hotel_bookings >= MAX_DAILY_HOTEL_BOOKINGS:
                errors.insert(-1, "Our Hotel is unavailable for this day. Please pick another date.")
        if "Zoo" in form:
            if date_details.zoo_bookings >= MAX_DAILY_ZOO_BOOKINGS:
                errors.insert(-1, "Our Zoo is unavailable for this day. Please pick another date.")
    else:
        new_booking_date = Bookings(formatted_date, 0, 0)
        date_details = new_booking_date
        db.session.add(new_booking_date)

    if len(errors) == 0:
        if "Hotel" in form:
            date_details.hotel_bookings += 1

        if "Zoo" in form:
            date_details.zoo_bookings += 1

    return errors


def verify_login():
    if "location" in session and "token" in session:
        users = User.query.filter_by(email=session["location"]).count()
        if users == 0:
            session.clear()
    else:
        session.clear()


@app.route("/", methods=["GET", "POST"])
def index():
    messages = []
    verify_login()
    if request.method == "POST":
        messages.insert(-1, "Thanks! We have received your message and will get back to you shortly.")

    return render_template("index.html", messages=messages)


@app.route("/zoo", methods=["GET", "POST"])
def zoo():
    messages = []
    verify_login()
    if request.method == "POST":
        messages.insert(-1, "Thanks! We have received your message and will get back to you shortly.")
    return render_template("zoo.html", messages=messages)


@app.route("/hotel", methods=["GET", "POST"])
def hotel():
    messages = []
    verify_login()
    if request.method == "POST":
        messages.insert(-1, "Thanks! We have received your message and will get back to you shortly.")

    return render_template("hotel.html", messages=messages)


@app.route("/educational", methods=["GET", "POST"])
def educational():
    messages = []
    verify_login()
    if request.method == "POST":
        messages.insert(-1, "Thanks! We have received your message and will get back to you shortly.")

    return render_template("educational.html",
                           messages=messages)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html")


@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    verify_login()
    if "token" not in session:
        return redirect(url_for("login"))

    """
    It is more secure to put all of this on one line so it is harder to understand. It also means raw values
    are not stored in variables when decrypting.
    When deployed to a production server, this should be removed. It is only here for convenience.
    unencryptedPassword = decryptString(bytes(session["token"]), globalAESKey).decode("utf-8")
    aesKey = getAesKeyFromPassword(unencryptedPassword).encode("utf-8")
    name = decryptString(user.name, aesKey)
    """

    user = User.query.filter_by(email=session["location"]).first()
    aes_key_bytes = get_aes_key_from_password(decrypt_string(bytes(session["token"]), global_aes_key).decode("utf-8"))
    aes_key = aes_key_bytes.encode("utf-8")
    name = decrypt_string(user.name, aes_key).decode("utf-8")
    loyalty_points = user.loyalty_points
    booking_data = json.loads(user.user_bookings)
    if request.method == "POST":
        cancelled_date = request.form["date"]
        loyalty_points -= 10
        del booking_data[cancelled_date]
        user.user_bookings = json.dumps(booking_data)
        user.loyalty_points = loyalty_points
        db.session.commit()

    for date in booking_data:
        current_date = datetime.now().date()
        booking_date = datetime.strptime(date, "%d-%m-%Y").date()
        booking_data[date]["Passed"] = not (booking_date >= current_date)

    return render_template("bookings.html",
                           name=name,
                           loyaltyPoints=loyalty_points,
                           bookingData=booking_data)


# Using a JSON to save bookings is bad practice
# This should definitely be changed to use linked databases instead
@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    verify_login()
    if "token" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        form = request.form

        if "Message" in form:
            messages = []
            messages.insert(-1, "Thanks! We have received your message and will get back to you shortly.")
            return render_template("tickets.html", messages=messages)

        errors = check_booking_details(form)
        if len(errors) > 0:
            return render_template("tickets.html",
                                   errors=errors,
                                   adultTicketPrice=ADULT_TICKET_PRICE,
                                   childTicketPrice=CHILD_TICKET_PRICE)

        user = User.query.filter_by(email=session["location"]).first()
        date = reformat_date(form["date"])
        adult_tickets = form["Adult"]
        child_tickets = form["Child"]
        total_price = (int(adult_tickets) * ADULT_TICKET_PRICE) + (int(child_tickets) * CHILD_TICKET_PRICE)
        booking_type = {"Hotel": ("Hotel" in form), "Zoo": ("Zoo" in form)}
        booking_info = {
            "Tickets": {
                "Adult": adult_tickets,
                "Child": child_tickets
            },
            "Price": total_price,
            "BookingType": booking_type
        }

        user_bookings = json.loads(user.user_bookings)
        user_bookings[date] = booking_info
        user.user_bookings = json.dumps(user_bookings)
        user.loyalty_points += 10
        db.session.commit()
        return redirect(url_for("bookings"))

    return render_template("tickets.html",
                           adultTicketPrice=ADULT_TICKET_PRICE,
                           childTicketPrice=CHILD_TICKET_PRICE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        form = request.form
        # print(request.form)
        if "signupEmail" in form:
            name = form["signupName"]
            email = form["signupEmail"]
            password = form["signupPassword"]
            errors = new_signup(name, email, password)

            if len(errors) > 0:
                # print(errors)
                return render_template("login.html",
                                       errors=errors)

            return render_template("login.html",
                                   messages=["Signup successful! Please login."])
            # print("New account created successfully!")
        elif "loginEmail" in form:
            errors = []
            email = form["loginEmail"]
            password = form["loginPassword"]
            hashed_password = hash_encrypt_string(password)
            hashed_email = hash_encrypt_string(email)
            entries = User.query.filter_by(hashed_email=hashed_email)
            if entries.count() > 0:
                user = entries.first()
                if user.hashed_password == hashed_password:
                    session["token"] = user.password
                    session["location"] = user.email
                else:
                    errors.insert(-1, "Incorrect Email or Password.")
            else:
                errors.insert(-1, "Account does not exist.")

            if len(errors) > 0:
                return render_template("login.html",
                                       errors=errors,
                                       email=email)

    if "token" in session:
        return redirect(url_for("bookings"))

    return render_template("login.html")


with app.app_context():
    db.create_all()
    db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
