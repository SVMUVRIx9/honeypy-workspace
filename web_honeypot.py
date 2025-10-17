# Libraries 
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request

# Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

# HTTP Logger
funnel_logger = logging.getLogger("HTTP Logger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Baseline honeypot
def web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)

    @app.route('/')
    def index():
        # Make sure wp-admin.html is in a "templates" folder
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        funnel_logger.info(
            f'Client with IP Address: {ip_address} entered\nUsername: {username}, Password: {password}'
        )

        if username == input_username and password == input_password:
            return "Welcome admin! (simulated)"
        else:
            return "Invalid username or password. Please try again."
        
    return app


def run_web_honeypot(port=5000, input_username="admin", input_password="password"):
    app = web_honeypot(input_username, input_password)
    app.run(debug=True, port=port, host="0.0.0.0")


if __name__ == "__main__":
    run_web_honeypot(port=5000, input_username="admin", input_password="password")
