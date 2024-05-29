import plotly.graph_objects as go
import streamlit as st
import sqlite3
from helper import *
import hashlib

# Database setup
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
    )
''')
conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password):
    hashed_password = hash_password(password)
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
    return c.fetchone() is not None

def register_user(username, password):
    hashed_password = hash_password(password)
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def reset_password(username, new_password):
    hashed_password = hash_password(new_password)
    c.execute('UPDATE users SET password=? WHERE username=?', (hashed_password, username))
    conn.commit()
    return c.rowcount > 0

st.set_page_config(
    page_title="Stock Price Prediction",
    page_icon="📈",
)

if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False

# Authentication
username = st.text_input("Username:", key="auth_username_input")
password = st.text_input("Password:", type="password", key="auth_password_input")
login_button = st.button("Login", key="auth_login_button")

if login_button:
    if authenticate(username, password):
        st.session_state.is_authenticated = True
    else:
        st.error("Invalid credentials. Please try again.")

if st.session_state.is_authenticated:
    st.sidebar.markdown("## **Welcome, Back User**")

    stock_dict = fetch_stocks()
    st.sidebar.markdown("### **Select stock**")
    stock = st.sidebar.selectbox("Choose a stock", list(stock_dict.keys()), key="sidebar_stock_select")

    st.sidebar.markdown("### **Select stock exchange**")
    stock_exchange = st.sidebar.radio("Choose a stock exchange", ("BSE", "NSE"), index=0, key="sidebar_stock_exchange_select")

    stock_ticker = f"{stock_dict[stock]}.{'BO' if stock_exchange == 'BSE' else 'NS'}"

    st.sidebar.markdown("### **Stock ticker**")
    st.sidebar.text_input(
        label="Stock ticker code", placeholder=stock_ticker, disabled=True, key="sidebar_stock_ticker_input"
    )

    periods = fetch_periods_intervals()

    st.sidebar.markdown("### **Select period**")
    period = st.sidebar.selectbox("Choose a period", list(periods.keys()), key="sidebar_period_select")

    st.sidebar.markdown("### **Select interval**")
    interval = st.sidebar.selectbox("Choose an interval", periods[period], key="sidebar_interval_select")

    st.markdown("# **Stock Price Prediction**")

    stock_data = fetch_stock_history(stock_ticker, period, interval)

    st.markdown("## **Historical Data**")

    fig = go.Figure(
        data=[
            go.Candlestick(
                x=stock_data.index,
                open=stock_data["Open"],
                high=stock_data["High"],
                low=stock_data["Low"],
                close=stock_data["Close"],
            )
        ]
    )

    fig.update_layout(xaxis_rangeslider_visible=False)

    st.plotly_chart(fig, use_container_width=True)

    train_df, test_df, forecast, predictions = generate_stock_prediction(stock_ticker)

    if (
        train_df is not None
        and (forecast >= 0).all()
        and (predictions >= 0).all()
    ):
        st.markdown("## **Stock Prediction**")

        fig = go.Figure(
            data=[
                go.Scatter(
                    x=train_df.index,
                    y=train_df["Close"],
                    name="Train",
                    mode="lines",
                    line=dict(color="blue"),
                ),
                go.Scatter(
                    x=test_df.index,
                    y=test_df["Close"],
                    name="Test",
                    mode="lines",
                    line=dict(color="orange"),
                ),
                go.Scatter(
                    x=forecast.index,
                    y=forecast,
                    name="Forecast",
                    mode="lines",
                    line=dict(color="red"),
                ),
                go.Scatter(
                    x=test_df.index,
                    y=predictions,
                    name="Test Predictions",
                    mode="lines",
                    line=dict(color="green"),
                ),
            ]
        )

        fig.update_layout(xaxis_rangeslider_visible=False)

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.markdown("## **Stock Prediction**")
        st.markdown("### **No data available for the selected stock**")
else:
    st.warning("Please log in to access the application.")
    st.warning("Demo username = 'user1', Demo password = '1234'")

    with st.expander("Register"):
        new_username = st.text_input("New Username:", key="register_new_username_input")
        new_password = st.text_input("New Password:", type="password", key="register_new_password_input")
        register_button = st.button("Register", key="register_button")

        if register_button:
            if register_user(new_username, new_password):
                st.success("Registration successful. Please log in.")
            else:
                st.error("Username already exists. Please choose a different username.")

    with st.expander("Reset Password"):
        reset_username = st.text_input("Username for password reset:", key="reset_username_input")
        reset_new_password = st.text_input("New Password:", type="password", key="reset_new_password_input")
        reset_password_button = st.button("Reset Password", key="reset_password_button")

        if reset_password_button:
            if reset_password(reset_username, reset_new_password):
                st.success("Password reset successful. Please log in with your new password.")
            else:
                st.error("Username not found. Please check the username.")
