from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# 🔥 CLEAR OLD DATA ON DASHBOARD START
with open("alerts.json", "w") as f:
    f.write("[]")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def data():
    try:
        with open("alerts.json", "r") as f:
            return json.load(f)
    except:
        return []

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
