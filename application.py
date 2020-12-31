from datetime import datetime
import os
import sqlite3
from sqlite3 import Row

from flask import (
    Flask, flash, redirect, render_template, request, session, g)
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import (
    default_exceptions, HTTPException, InternalServerError)
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
# app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLite database
# db = SQL("sqlite:///finance.db")
DATABASE = "finance.db"


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    db = get_db()
    owned_shares = get_user_shares(session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?",
                      [session["user_id"]]).fetchone()["cash"]
    assets = cash
    shares = []
    for share in owned_shares:
        stockinfo = lookup(share["symbol"])
        assert stockinfo
        share = {**stockinfo, **share}
        share["total"] = stockinfo["price"] * share["shares"]
        assets += share["total"]
        share["price"] = usd(share["price"])
        share["total"] = usd(share["total"])
        shares.append(share)
    return render_template(
        "index.html", shares=shares, cash=usd(cash), assets=usd(assets))


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("changePassword.html")
    current = request.form.get("current")
    new = request.form.get("new")
    confirmation = request.form.get("confirmation")

    if not all([current, new, confirmation]):
        return apology("Fill in all input fields")

    if new != confirmation:
        return apology("Confirmation password is wrong")

    db = get_db()
    actual = db.execute("SELECT hash FROM users WHERE id = ?", [
                        session["user_id"]]).fetchone()['hash']
    if not check_password_hash(actual, current):
        return apology("Your passwords don't match", 403)

    hashed_password = generate_password_hash(new)
    db.execute("UPDATE users SET hash = ? WHERE id = ?",
               [hashed_password, session["user_id"]])
    db.commit()
    flash("Your password has been successfully updated.")
    return redirect("/login")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    symbol = request.form.get("symbol")
    shares_count = request.form.get("shares", type=int)
    # Values check
    if not all([symbol, shares_count]):
        return apology("Fill in all input fields")
    if shares_count < 0:
        return apology("Shares must be a positive number")
    stockinfo = lookup(symbol)
    if not stockinfo:
        return apology("Invalid symbol")
    cost = stockinfo["price"] * shares_count
    user = get_user_info(session["user_id"])
    cash = user['cash']
    if cash < cost:
        return apology("Unsufficient funds")

    make_transaction(user, shares_count, stockinfo)
    flash("Your purchase was successful.")
    return redirect("/")


def get_user_info(user_id):
    db = get_db()
    user = dict(db.execute(
        "SELECT cash FROM users WHERE id = ?",
        [user_id]).fetchone())
    return user


def get_user_shares(user_id):
    db = get_db()
    shares = db.execute(
        "SELECT symbol, shares FROM shares WHERE user_id = ?",
        [session["user_id"]]).fetchall()
    return shares


def make_transaction(user: dict, shares_count: int, stockinfo: dict):
    """Make transactions in database to buy or sell stocks.
    If `shares_count` < 0 -> sell stocks.
    If `shares_count` > 0 -> buy stocks.

    :param user: User info dictionary from db.
    :type user: dict
    :param symbol: Stock symbol
    :type symbol: str
    :param shares_count: Amount of shares to buy/sell.
    :type shares_count: int
    :param stockinfo: Current information about stock.
    :type stockinfo: dict
    :return: returns True if everything is OK.
    :rtype: bool
    """

    assert shares_count  # Check if null
    buying = True if shares_count > 0 else False
    user_id = session["user_id"]
    db = get_db()
    cash = user['cash']
    cost = stockinfo["price"] * shares_count
    symbol = stockinfo["symbol"]
    # If buying
    balance = cash - cost
    # Update user money
    db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
               dict(cash=balance, user_id=user_id))

    # Find matching share
    share = db.execute(
        "SELECT * FROM shares WHERE user_id = :user_id AND symbol = :symbol",
        dict(user_id=user_id, symbol=symbol)).fetchone()
    if not share:
        if not buying:
            raise ValueError("You don't have stocks.")
        # If buying for the first time
        db.execute("INSERT INTO shares VALUES (?, ?, ?)",
                   [user_id, symbol, shares_count])
    else:
        if not buying and share["shares"] < -shares_count:
            raise ValueError("You don't have enough stocks")
        total_shares = share["shares"] + shares_count
        db.execute(
            "UPDATE shares SET shares = :shares\
                WHERE user_id = :user_id AND symbol = :symbol",
            dict(shares=total_shares, user_id=user_id, symbol=symbol))

    # Add transaction info
    db.execute(
        "INSERT INTO transactions (user_id, symbol, shares, price, timestamp)\
            VALUES (?, ?, ?, ?, ?)",
        [user_id, symbol, shares_count, stockinfo["price"], datetime.now()])
    db.commit()
    return True


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    db = get_db()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        [session["user_id"]]).fetchall()
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        db = get_db()
        rows = db.execute(
            "SELECT * FROM users WHERE username = :username",
            dict(username=request.form.get("username"))).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
                rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        flash("You were successfully logged in.")
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Fill in symbol field")
    stock = lookup(symbol)
    if not stock:
        return apology("Invalid symbol")
    stock["price"] = usd(stock["price"])
    return render_template("quote.html", stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # If user is already logged in redirect him.
    if session.get("user_id"):
        return redirect("/")

    if request.method == "GET":
        return render_template("register.html")

    # Else there is POST method
    username = request.form.get('username')
    password = request.form.get('password')
    confirmation = request.form.get('confirmation')
    # Check for errors
    if not all([username, password, confirmation]):
        return apology("Please fill in all input fields.")
    if password != confirmation:
        return apology("Your passwords don't match.")
    db = get_db()
    rows = db.execute(
        "SELECT username FROM users WHERE username = :username",
        dict(username=username))
    if rows.fetchall():
        return apology("Username %s already exists" % username)

    # Add user
    hashed_password = generate_password_hash(password)
    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
               [username, hashed_password])
    db.commit()

    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    db = get_db()
    if request.method == "GET":
        shares = map(lambda x: x["symbol"], db.execute(
            "SELECT symbol FROM shares WHERE user_id = ? AND shares > 0",
            [user_id]).fetchall())
        return render_template("sell.html", shares=shares)

    symbol = request.form.get("symbol")
    shares_count = request.form.get("shares", type=int)
    stockinfo = lookup(symbol)
    if not all([shares_count, symbol]) or shares_count < 0:
        return apology("Fill in all input fields")
    if shares_count < 0:
        return apology("Please enter valid number")
    if not stockinfo:
        return apology("Invalid symbol")

    share = db.execute(
        "SELECT * FROM shares WHERE user_id = ? AND symbol = ?",
        [user_id, symbol]).fetchone()
    if not share:
        return apology("You don't have enough shares")
    if share["shares"] < shares_count:
        return apology("You don't have enough shares")

    user = get_user_info(user_id)
    make_transaction(user, -shares_count, stockinfo)
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
