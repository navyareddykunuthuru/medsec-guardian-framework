
# MedCrypt - Lightweight Hybrid Cryptographic Framework

A secure web application for medical data encryption, authentication, and image watermarking. This framework integrates ASCON encryption, ECC key exchange, modified RSA authentication, and digital watermarking to enhance security and efficiency in healthcare applications.

## Features

- **ASCON Encryption**: Lightweight and high-speed encryption for medical data
- **ECC Key Exchange**: Secure exchange of encryption keys
- **Modified RSA Authentication**: Enhanced authentication with reduced risk
- **Digital Watermarking**: Protect medical images from unauthorized modifications
- **User Management**: Admin interface for user management and activity logs
- **Two-Layer Encryption**: Comprehensive security for patient data

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd medcrypt
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Run the application:
```
python app.py
```

5. Access the web interface at http://127.0.0.1:5000

## Usage

### Admin Access

- Username: admin
- Password: admin123

### Demo User Accounts

- Username: user1 / Password: password1
- Username: user2 / Password: password2

### Note on Security Implementation

This demo implements mock cryptographic functions for demonstration purposes. In a production environment, you should integrate actual ASCON, ECC, and RSA libraries for proper security.

## Technology Stack

- Flask (Python web framework)
- OpenCV (for image processing)
- NumPy (for mathematical operations)
- Pillow (for image manipulation)
- Bootstrap 5 (for responsive UI)
- Font Awesome (for icons)

## Security Considerations

- This is a demonstration framework and should be further hardened for production use
- Proper key management systems should be implemented in real-world applications
- Additional authentication mechanisms are recommended for production deployments

## License

[MIT License](LICENSE)
