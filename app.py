
import streamlit as st

st.set_page_config(
    page_title="Stock Prediction App",
    page_icon="📈",
)




import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pandas_datareader as data
import streamlit as st
from yahoo_fin import stock_info





import yfinance as yf

start = '2010-01-01'
end = '2020-12-31'

st.title('Stock Price Prediction')

user_input=st.text_input('Enter Stock','AAPL')
df = yf.download(user_input, start=start, end=end)


st.subheader('Past 10 years Data')
st.write(df.describe())

st.subheader('Stock Rate')
ma100=df.Close.rolling(100).mean()
ma200=df.Close.rolling(200).mean()
fig=plt.figure(figsize=(12,6))
plt.plot(ma100)
plt.plot(ma200)
plt.plot(df.Close)
st.pyplot(fig)

df['Open-Close']= df.Close - df.Open
df['High-Low']  = df.High - df.Low
df = df.dropna()
X= df[['Open-Close', 'High-Low']]
X.head()

Y= np.where(df['Adj Close'].shift(-1)>df['Adj Close'],1,-1)


split_percentage = 0.8
split = int(split_percentage*len(df))
X_train = X[:split]
Y_train = Y[:split]

X_test = X[split:]
Y_test = Y[split:]

from sklearn.ensemble import RandomForestClassifier
rfc= RandomForestClassifier(n_estimators=16)
rfc.fit(X_train, Y_train)
rfc_pred=rfc.predict(X_test)

predicted = rfc.predict(X_test)

st.subheader('Predictions')
fig2=plt.figure(figsize=(12,6))
plt.plot(Y_test, 'b', label='Actual Price')
plt.plot(predicted,'r',label='Predicted Price')
plt.xlabel('Time')
plt.ylabel('Price')
plt.legend()
st.pyplot(fig2)


a=stock_info.get_live_price(user_input)

st.subheader("PREDICTED PRICE:")
st.subheader(a)

