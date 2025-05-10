
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
import os
import hashlib
import secrets
import base64
import json
from datetime import datetime
import cv2
import numpy as np
import io
from PIL import Image
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Create necessary directories
os.makedirs('uploads', exist_ok=True)
os.makedirs('encrypted', exist_ok=True)
os.makedirs('watermarked', exist_ok=True)

# Admin credentials (hardcoded as requested)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# In-memory database for users and logs
users_db = {}
history_logs = []

# Mock implementations of cryptographic functions
def ascon_encrypt(data, key):
    """Mock ASCON encryption (for demonstration)"""
    # In a real implementation, use an actual ASCON library
    mock_encrypted = hashlib.sha256((data + key).encode()).hexdigest()
    return mock_encrypted

def ascon_decrypt(encrypted_data, key):
    """Mock ASCON decryption (for demonstration)"""
    # This is just a mock - in real implementation use actual ASCON
    return f"Decrypted data using key: {key}"

def ecc_key_exchange(public_key):
    """Mock ECC key exchange"""
    # Generate a mock shared key
    return hashlib.sha256(public_key.encode()).hexdigest()[:16]

def rsa_authenticate(data, signature):
    """Mock RSA authentication"""
    # In a real implementation, verify with RSA
    return True

def apply_watermark(image_data, watermark_text):
    """Apply a digital watermark to an image"""
    try:
        # Convert bytes to image
        image = Image.open(io.BytesIO(image_data))
        img_array = np.array(image)
        
        # Convert to BGR for OpenCV if needed
        if len(img_array.shape) == 3 and img_array.shape[2] == 3:
            img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        
        # Add watermark text
        watermarked = cv2.putText(
            img_array, watermark_text, (50, 50), 
            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2, cv2.LINE_AA
        )
        
        # Convert back to RGB for PIL
        if len(watermarked.shape) == 3 and watermarked.shape[2] == 3:
            watermarked = cv2.cvtColor(watermarked, cv2.COLOR_BGR2RGB)
        
        # Convert array back to image and then to bytes
        result_image = Image.fromarray(watermarked)
        img_byte_arr = io.BytesIO()
        result_image.save(img_byte_arr, format=image.format or 'PNG')
        
        # Return watermarked image bytes
        return img_byte_arr.getvalue()
    except Exception as e:
        print(f"Error in watermarking: {e}")
        return image_data  # Return original on error

def verify_watermark(image_data):
    """Verify if image contains a watermark (simplified)"""
    # In a real system, you'd extract and verify the watermark
    # This is just a placeholder
    return {"verified": True, "message": "Image watermark verified successfully"}

def log_activity(username, action, status):
    """Log user activity"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    history_logs.append({
        "timestamp": timestamp,
        "username": username,
        "action": action,
        "status": status
    })

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db and users_db[username]['password'] == password:
            session['username'] = username
            log_activity(username, "Login", "Success")
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            log_activity(username, "Login", "Failed")
    
    return render_template('login.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = username
            session['is_admin'] = True
            log_activity("admin", "Admin Login", "Success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials')
            log_activity(username, "Admin Login", "Failed")
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        log_activity(session['username'], "Logout", "Success")
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html')

@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if username in users_db:
            flash('Username already exists')
        else:
            users_db[username] = {
                'password': password,
                'email': email,
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            flash('User added successfully')
            log_activity("admin", f"Added user: {username}", "Success")
    
    return render_template('manage_users.html', users=users_db)

@app.route('/admin/logs')
def view_logs():
    if not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    return render_template('view_logs.html', logs=history_logs)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files and not request.form.get('text_data'):
            flash('No file or text provided')
            return redirect(request.url)
        
        key = request.form['encryption_key']
        
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
        else:
            data = request.form['text_data']
            filename = f"text_data_{uuid.uuid4().hex}.txt"
        
        # Perform encryption
        encrypted_data = ascon_encrypt(data, key)
        
        # Generate ECC shared key
        ecc_public_key = request.form['ecc_public_key']
        shared_key = ecc_key_exchange(ecc_public_key)
        
        # RSA Authentication
        rsa_signature = request.form['rsa_signature']
        is_authenticated = rsa_authenticate(data, rsa_signature)
        
        # Save encrypted data
        encrypted_file = os.path.join('encrypted', f"encrypted_{filename}")
        with open(encrypted_file, 'w') as f:
            f.write(encrypted_data)
        
        log_activity(session['username'], f"Encrypted file: {filename}", "Success")
        
        return render_template(
            'encrypt_result.html', 
            encrypted_data=encrypted_data,
            shared_key=shared_key,
            is_authenticated=is_authenticated,
            filename=encrypted_file
        )
    
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        key = request.form['decryption_key']
        
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)
            
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
                
            # Perform decryption
            decrypted_data = ascon_decrypt(encrypted_data, key)
            
            log_activity(session['username'], f"Decrypted file: {filename}", "Success")
            
            return render_template('decrypt_result.html', decrypted_data=decrypted_data)
        else:
            flash('No file provided')
    
    return render_template('decrypt.html')

@app.route('/watermark', methods=['GET', 'POST'])
def watermark():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file provided')
            return redirect(request.url)
        
        image_file = request.files['image']
        watermark_text = request.form['watermark_text']
        
        if image_file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if image_file:
            # Read image data
            image_data = image_file.read()
            
            # Apply watermark
            watermarked_image = apply_watermark(image_data, watermark_text)
            
            # Save watermarked image
            filename = secure_filename(image_file.filename)
            watermarked_path = os.path.join('watermarked', f"watermarked_{filename}")
            
            with open(watermarked_path, 'wb') as f:
                f.write(watermarked_image)
            
            log_activity(session['username'], f"Watermarked image: {filename}", "Success")
            
            # Prepare image for display
            encoded_img = base64.b64encode(watermarked_image).decode('utf-8')
            img_src = f"data:image/png;base64,{encoded_img}"
            
            return render_template(
                'watermark_result.html', 
                image_src=img_src,
                filename=watermarked_path
            )
    
    return render_template('watermark.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file provided')
            return redirect(request.url)
        
        image_file = request.files['image']
        
        if image_file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if image_file:
            # Read image data
            image_data = image_file.read()
            
            # Verify watermark
            verification_result = verify_watermark(image_data)
            
            # Prepare image for display
            encoded_img = base64.b64encode(image_data).decode('utf-8')
            img_src = f"data:image/png;base64,{encoded_img}"
            
            log_activity(session['username'], f"Verified image: {image_file.filename}", 
                         "Success" if verification_result['verified'] else "Failed")
            
            return render_template(
                'verify_result.html', 
                image_src=img_src,
                verified=verification_result['verified'],
                message=verification_result['message']
            )
    
    return render_template('verify.html')

@app.route('/download/<path:filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return send_file(filename, as_attachment=True)

# Add a few test users to start with
users_db["user1"] = {
    'password': 'password1',
    'email': 'user1@example.com',
    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

users_db["user2"] = {
    'password': 'password2',
    'email': 'user2@example.com',
    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

if __name__ == '__main__':
    app.run(debug=True)
