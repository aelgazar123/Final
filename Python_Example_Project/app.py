from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired
from scapy.all import sniff, IP
import numpy as np
from werkzeug.utils import secure_filename
import pandas as pd 
import os
from flask import render_template, flash
from datetime import datetime
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
socketio = SocketIO(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'user_models'
ALLOWED_EXTENSIONS = {'pkl', 'h5'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
captured_packets = []
time_interval = 1
def calculate_average_rate(value, delta, time_interval):
    if time_interval == 0:
        return 0
    return delta / time_interval

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        forward_packets = packet[IP].len  # Assuming IP length as the number of forward packets
        forward_bytes = packet[IP].len
        reverse_packets = 0  # Replace with actual reverse packets if available in the packet
        reverse_bytes = 0  # Replace with actual reverse bytes if available in the packet

        # Calculate deltas
        delta_forward_packets = forward_packets - captured_packets[-1]['forward_packets'] if captured_packets else 0
        delta_forward_bytes = forward_bytes - captured_packets[-1]['forward_bytes'] if captured_packets else 0
        delta_reverse_packets = reverse_packets - captured_packets[-1]['reverse_packets'] if captured_packets else 0
        delta_reverse_bytes = reverse_bytes - captured_packets[-1]['reverse_bytes'] if captured_packets else 0

        # Calculate instantaneous rates
        forward_instantaneous_packets_per_second = calculate_average_rate(delta_forward_packets, 1, time_interval)
        forward_instantaneous_bytes_per_second = calculate_average_rate(delta_forward_bytes, 1, time_interval)
        reverse_instantaneous_packets_per_second = calculate_average_rate(delta_reverse_packets, 1, time_interval)
        reverse_instantaneous_bytes_per_second = calculate_average_rate(delta_reverse_bytes, 1, time_interval)

        # Calculate average rates
        forward_average_packets_per_second = calculate_average_rate(forward_packets, captured_packets[-1]['forward_packets'], time_interval)
        forward_average_bytes_per_second = calculate_average_rate(forward_bytes, captured_packets[-1]['forward_bytes'], time_interval)
        reverse_average_packets_per_second = calculate_average_rate(reverse_packets, captured_packets[-1]['reverse_packets'], time_interval)
        reverse_average_bytes_per_second = calculate_average_rate(reverse_bytes, captured_packets[-1]['reverse_bytes'], time_interval)

        # Add the data to the captured_packets list
        captured_packets.append({
            'timestamp': timestamp,
            'forward_packets': forward_packets,
            'forward_bytes': forward_bytes,
            'delta_forward_packets': delta_forward_packets,
            'delta_forward_bytes': delta_forward_bytes,
            'forward_instantaneous_packets_per_second': forward_instantaneous_packets_per_second,
            'forward_average_packets_per_second': forward_average_packets_per_second,
            'forward_instantaneous_bytes_per_second': forward_instantaneous_bytes_per_second,
            'forward_average_bytes_per_second': forward_average_bytes_per_second,
            'reverse_packets': reverse_packets,
            'reverse_bytes': reverse_bytes,
            'delta_reverse_packets': delta_reverse_packets,
            'delta_reverse_bytes': delta_reverse_bytes,
            'reverse_instantaneous_packets_per_second': reverse_instantaneous_packets_per_second,
            'reverse_average_packets_per_second': reverse_average_packets_per_second,
            'reverse_instantaneous_bytes_per_second': reverse_instantaneous_bytes_per_second,
            'reverse_average_bytes_per_second': reverse_average_bytes_per_second,
            'traffic_type': 'voice'  # Replace with your actual traffic type extraction logic
        })

        # Emit the data to connected clients using SocketIO
        socketio.emit('packet_data', captured_packets[-1])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    users = {
        1: User(id=1, username='user', password='password')
    }
    return users.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class PredictionForm(FlaskForm):
    feature1 = StringField('Feature 1', validators=[DataRequired()])
    feature2 = StringField('Feature 2', validators=[DataRequired()])
    submit = SubmitField('Predict')

class ModelUploadForm(FlaskForm):
    file = FileField('Upload Model', validators=[DataRequired()])
    submit = SubmitField('Upload')

class DatasetUploadForm(FlaskForm):
    file = FileField('Upload Dataset', validators=[DataRequired()])
    submit = SubmitField('Upload')

@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        form = PredictionForm()
        if form.validate_on_submit():
            # Your prediction logic here
            return render_template('index.html', form=form, prediction_text='Your prediction result')
        return render_template('index.html', form=form)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = load_user(1)
        if user and user.password == form.password.data:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Check your username and password.', 'danger')

    return render_template('login.html', form=form)
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/network_traffic')
@login_required
def network_traffic():
    return render_template('network_traffic.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = form.password.data
        user = User(id=2, username=form.username.data, password=hashed_password)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/upload_model', methods=['GET', 'POST'])
@login_required
def upload_model():
    form = ModelUploadForm()

    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flash(f'Model {filename} uploaded successfully', 'success')
            # You may want to reload the models or update the list of available models

    return render_template('upload_model.html', form=form)

@app.route('/upload_dataset', methods=['GET', 'POST'])
@login_required
def upload_dataset():
    form = DatasetUploadForm()

    if form.validate_on_submit():
        file = form.file.data
        if file:
            try:
                # Read the uploaded CSV file using pandas
                df = pd.read_csv(file)

                # Render the dataset table with the uploaded data
                return render_template('dataset_table.html', table=df.to_html(classes='table table-striped'))

            except pd.errors.EmptyDataError:
                flash('Uploaded file is empty!', 'danger')
        else:
            flash('No file uploaded!', 'danger')

    return render_template('upload_dataset.html', form=form)

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    # Add logic to get the list of available models
    available_models = [...]  # List of available models (file paths or names)

    if request.method == 'POST':
        selected_model = request.form.get('model_select')
        # Use the selected model for prediction
        # ...

    return render_template('predict.html', available_models=available_models)

@socketio.on('packet_data')
def handle_packet(data):
    emit('update_packets', data, broadcast=True)

def packet_callback(packet):
    if IP in packet:
        packet_data = f"Source: {packet[IP].src}, Destination: {packet[IP].dst}"
        socketio.emit('packet_data', packet_data)

if __name__ == '__main__':
    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff, kwargs={"prn": packet_callback, "store": 0})
    sniff_thread.start()

    # Run the Flask app with SocketIO
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)