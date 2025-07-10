import os
import sqlite3
import datetime
import requests
from flask import Flask, request, render_template, redirect, session, url_for
import stripe

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me'

# Environment variables - set these in your environment
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
GROK_API_KEY = os.environ.get('GROK_API_KEY')
DOMAIN = 'http://127.0.0.1:5000'  # Change to your domain

stripe.api_key = STRIPE_SECRET_KEY

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY, email TEXT UNIQUE, subscribed INTEGER DEFAULT 0, 
              queries_used INTEGER DEFAULT 0, last_reset TEXT)''')
conn.commit()

def get_user(email):
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if row:
        return {'id': row[0], 'email': row[1], 'subscribed': row[2], 'queries_used': row[3], 'last_reset': row[4]}
    return None

def update_queries(user_id):
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    last_reset = datetime.date.fromisoformat(user[4]) if user[4] else datetime.date.today()
    today = datetime.date.today()
    if (today.year > last_reset.year) or (today.month > last_reset.month):
        queries = 1
        last_reset = today.isoformat()
    else:
        queries = user[3] + 1
    c.execute("UPDATE users SET queries_used=?, last_reset=? WHERE id=?", (queries, last_reset, user_id))
    conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user(email)
        if not user:
            c.execute("INSERT INTO users (email, last_reset) VALUES (?, ?)", (email, datetime.date.today().isoformat()))
            conn.commit()
        session['email'] = email
        return redirect('/analyze')
    return render_template('login.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if 'email' not in session:
        return redirect('/login')
    user = get_user(session['email'])
    is_admin = session.get('admin', False)
    if is_admin or user['subscribed']:
        if not is_admin and user['queries_used'] >= 20:
            return redirect('/subscribe')
        if request.method == 'POST':
            contract = request.form['contract']
            prompt = f"\n\nHuman: Analyze this contract for potential disputes, risks, and suggestions:\n{contract}\n\nAssistant:"
            headers = {'Authorization': f'Bearer {GROK_API_KEY}', 'Content-Type': 'application/json'}
            data = {"model": "grok-4", "max_tokens_to_sample": 2000, "temperature": 0.7, "prompt": prompt}
            resp = requests.post('https://api.x.ai/v1/complete', json=data, headers=headers)
            if resp.status_code == 200:
                analysis = resp.json().get('completion', 'Error in analysis.')
            else:
                analysis = 'API error.'
            update_queries(user['id'])
            return render_template('analyze.html', analysis=analysis)
        return render_template('analyze.html')
    else:
        return redirect('/subscribe')

@app.route('/subscribe')
def subscribe():
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[
            {
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': 999,
                    'product_data': {
                        'name': 'AI Contract Analyzer Subscription',
                    },
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            },
        ],
        mode='subscription',
        success_url=DOMAIN + '/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=DOMAIN + '/cancel',
    )
    return render_template('subscribe.html', session_id=checkout_session.id, stripe_pk=STRIPE_PUBLISHABLE_KEY)

@app.route('/success')
def success():
    if 'email' in session:
        c.execute("UPDATE users SET subscribed=1, queries_used=0, last_reset=? WHERE email=?", (datetime.date.today().isoformat(), session['email']))
        conn.commit()
    return redirect('/analyze')

@app.route('/cancel')
def cancel():
    return redirect('/')

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return '', 400
    except stripe.error.SignatureVerificationError:
        return '', 400
    # Handle events if needed, for MVP we handle in success
    return '', 200

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form['password']
        if password == 'Tennis345!':
            session['admin'] = True
            return redirect('/analyze')
        else:
            return 'Invalid password', 403
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
