
from app import app

if __name__ == '__main__':
    print("Starting the MedCrypt server...")
    print("View the website at: http://127.0.0.1:5000")
    app.run(debug=True)
