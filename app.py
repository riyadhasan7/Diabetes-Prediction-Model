from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import mysql.connector
import joblib
import numpy as np


app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# ✅ Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ✅ Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'your-email-password'  # Change this

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# ✅ Connect to MySQL Database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="riad3214321?",
    database="diabetes_db",
    auth_plugin="mysql_native_password"
)
cursor = db.cursor()


# ✅ Load the Trained Model
model = joblib.load('model.pkl')


# ✅ User Class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(*user)
    return None


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))

        # ✅ Debugging print statements
        print(f"Username: {username}, Email: {email}, Password: {password}")

        # ✅ Hash password before storing in the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        print(f"Hashed Password: {hashed_password}")  # ✅ Print hashed password for debugging

        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash) 
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))

            db.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as e:
            flash(f"Database Error: {str(e)}", "danger")
            db.rollback()

    return render_template('signup.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor.execute("SELECT id, username, email, password_hash FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[3], password):
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password.", "danger")

    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # ✅ Check if the email exists in the database
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)

            # ✅ Send reset email
            msg = Message("Password Reset Request",
                          sender="your-email@gmail.com",
                          recipients=[email])
            msg.body = f"Click the link below to reset your password:\n{reset_url}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for('login'))
        else:
            flash("No account found with that email.", "danger")

    return render_template('forgot_password.html')



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # ✅ Link expires in 1 hour
    except Exception:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # ✅ Update password in MySQL
        cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_password, email))
        db.commit()

        flash("Your password has been updated! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)






# ✅ Prediction Route - Stores Predictions in MySQL
@app.route('/predict', methods=['POST'])
def predict():
    if not current_user.is_authenticated:
        flash("You need to log in before making a prediction.", "warning")
        return redirect(url_for('login'))

    try:
        # ✅ Extract user input (Adding debug print statements)
        age = request.form.get('age')
        bmi = request.form.get('bmi')
        HbA1c_level = request.form.get('HbA1c_level')
        blood_glucose_level = request.form.get('blood_glucose_level')
        gender = request.form.get('gender')
        smoking_history = request.form.get('smoking_history')
        heart_disease = request.form.get('heart_disease')
        hypertension = request.form.get('hypertension')

        print(f"DEBUG: Received Input - Age={age}, BMI={bmi}, HbA1c={HbA1c_level}, Glucose={blood_glucose_level}")
        print(f"DEBUG: Gender={gender}, Smoking={smoking_history}, Heart Disease={heart_disease}, Hypertension={hypertension}")

        # ✅ Convert input to correct types
        try:
            age = float(age) if age else None
            bmi = float(bmi) if bmi else None
            HbA1c_level = float(HbA1c_level) if HbA1c_level else None
            blood_glucose_level = float(blood_glucose_level) if blood_glucose_level else None
            heart_disease = int(heart_disease) if heart_disease else 0
            hypertension = int(hypertension) if hypertension else 0
        except ValueError:
            flash("Invalid input values. Please enter valid numbers.", "danger")
            return redirect(url_for('home'))

        # ✅ One-hot encoding for categorical features
        gender_encoding = [1 if gender == "Female" else 0, 1 if gender == "Male" else 0, 1 if gender == "Other" else 0]
        smoking_encoding = [
            1 if smoking_history == "No Info" else 0,
            1 if smoking_history == "current" else 0,
            1 if smoking_history == "ever" else 0,
            1 if smoking_history == "former" else 0,
            1 if smoking_history == "never" else 0,
            1 if smoking_history == "not current" else 0
        ]
        heart_disease_encoding = [1 if heart_disease == 0 else 0, 1 if heart_disease == 1 else 0]
        hypertension_encoding = [1 if hypertension == 0 else 0, 1 if hypertension == 1 else 0]

        # ✅ Prepare input data for model
        input_data = np.array([
            age, bmi, HbA1c_level, blood_glucose_level,
            *gender_encoding, *smoking_encoding,
            *heart_disease_encoding, *hypertension_encoding
        ]).reshape(1, -1)

        print(f"DEBUG: Input Data for Model: {input_data}")

        # ✅ Check if the model is loaded properly
        if model is None:
            flash("Error: Model not loaded properly.", "danger")
            return redirect(url_for('home'))

        # ✅ Make prediction
        prediction = model.predict(input_data)
        print(f"DEBUG: Model Prediction: {prediction}")

        # ✅ **Apply Rule-Based Override (while keeping the ML model active)**
        if HbA1c_level >= 6.5 or blood_glucose_level >= 200:
            result = "Yes"  # Confirmed diabetes (Strict Threshold)
        elif 5.7 <= HbA1c_level < 6.5 or 140 <= blood_glucose_level < 200:
            result = "Yes" if prediction[0] == 1 else "No"  # ML Model Decides for Prediabetes Cases
        else:
            result = "No"  # Low-risk case, no diabetes

        # ✅ **NEW: Risk Level Calculation**
        if HbA1c_level >= 6.5 or blood_glucose_level >= 200:
            risk_level = "High Risk"
        elif 5.7 <= HbA1c_level < 6.5 or 140 <= blood_glucose_level < 200:
            risk_level = "Moderate Risk"
        else:
            risk_level = "Low Risk"

        # ✅ Store values in session for display on `/result`
        session.update({
            'prediction': result,
            'risk_level': risk_level,
            'age': age,
            'bmi': bmi,
            'HbA1c_level': HbA1c_level,
            'blood_glucose_level': blood_glucose_level,
            'gender': gender,
            'smoking_history': smoking_history,
            'heart_disease': heart_disease,
            'hypertension': hypertension
        })

        return redirect(url_for('result'))


    except Exception as e:
        flash(f"Prediction error: {str(e)}", "danger")
        return redirect(url_for('home'))




        # ✅ Check if `user_id` exists
        user_id = current_user.id if hasattr(current_user, 'id') else None
        if user_id is None:
            flash("Error: Unable to fetch user ID. Please log in again.", "danger")
            return redirect(url_for('login'))

        # ✅ Store user input & prediction in `user_records`
        cursor.execute("""
            INSERT INTO user_records (user_id, age, bmi, HbA1c_level, blood_glucose_level, 
                gender, smoking_history, heart_disease, hypertension, prediction) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, age, bmi, HbA1c_level, blood_glucose_level, gender, smoking_history, heart_disease, hypertension, result))

        db.commit()  # ✅ Save to database

        # ✅ Store prediction in session for display on `/result`
        session['prediction'] = result
        session['age'] = age
        session['bmi'] = bmi
        session['HbA1c_level'] = HbA1c_level
        session['blood_glucose_level'] = blood_glucose_level
        session['gender'] = gender
        session['smoking_history'] = smoking_history
        session['heart_disease'] = heart_disease
        session['hypertension'] = hypertension

        return redirect(url_for('result'))  # ✅ Redirect to `/result`

    except Exception as e:
        flash(f"Prediction error: {str(e)}", "danger")
        print(f"ERROR: {e}")  # ✅ Print error to Flask console
        db.rollback()
        return redirect(url_for('home'))




# ✅ Result Page - Displays Prediction
@app.route('/result')
def result():
    if not current_user.is_authenticated:
        flash("You need to log in before accessing results.", "warning")
        return redirect(url_for('login'))

    return render_template('result.html',
                           prediction=session.get('prediction'),
                           age=session.get('age'),
                           bmi=session.get('bmi'),
                           HbA1c_level=session.get('HbA1c_level'),
                           blood_glucose_level=session.get('blood_glucose_level'),
                           gender=session.get('gender'),
                           smoking_history=session.get('smoking_history'),
                           heart_disease=session.get('heart_disease'),
                           hypertension=session.get('hypertension'))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        flash("You need to log in before accessing the dashboard.", "warning")
        return redirect(url_for('login'))

    cursor.execute("""
        SELECT age, bmi, HbA1c_level, blood_glucose_level, gender, smoking_history, 
               heart_disease, hypertension, prediction, created_at 
        FROM user_records 
        WHERE user_id = %s ORDER BY created_at DESC
    """, (current_user.id,))

    records = cursor.fetchall()  # ✅ Get all user records

    # ✅ Extract data for charts
    dates = []
    hba1c_levels = []
    glucose_levels = []

    for record in records:
        dates.append(record[9].strftime("%Y-%m-%d"))  # Convert timestamp to string
        hba1c_levels.append(record[2])
        glucose_levels.append(record[3])

    return render_template('dashboard.html', records=records, dates=dates, hba1c_levels=hba1c_levels, glucose_levels=glucose_levels)


import pandas as pd
from flask import Response


@app.route('/export_csv')
@login_required
def export_csv():
    cursor.execute("""
        SELECT age, bmi, HbA1c_level, blood_glucose_level, gender, smoking_history, 
               heart_disease, hypertension, prediction, created_at 
        FROM user_records 
        WHERE user_id = %s ORDER BY created_at DESC
    """, (current_user.id,))

    records = cursor.fetchall()
    df = pd.DataFrame(records, columns=['Age', 'BMI', 'HbA1c Level', 'Blood Glucose', 'Gender',
                                        'Smoking History', 'Heart Disease', 'Hypertension', 'Prediction', 'Created At'])

    response = Response(df.to_csv(index=False), content_type='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=health_data.csv"
    return response


from flask import session, send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter


@app.route('/export_pdf')
def export_pdf():
    try:
        # ✅ Fetch user data from session
        user_name = session.get('user_name', 'Unknown User')
        age = session.get('age', 0)
        bmi = float(session.get('bmi', 0))
        HbA1c_level = float(session.get('HbA1c_level', 0))
        blood_glucose_level = float(session.get('blood_glucose_level', 0))
        smoking_history = session.get('smoking_history', 'No Info')
        prediction = session.get('prediction', 'No')

        # ✅ Determine Risk Level
        if HbA1c_level >= 6.5 or blood_glucose_level >= 200:
            risk_level = "High Risk"
        elif 5.7 <= HbA1c_level < 6.5 or 140 <= blood_glucose_level < 200:
            risk_level = "Moderate Risk (Pre-Diabetes)"
        else:
            risk_level = "Low Risk"

        # ✅ Generate personalized feedback
        feedback = f"Dear {user_name},\n\n"
        if risk_level == "High Risk":
            feedback += "⚠️ You are at HIGH risk for diabetes. It is strongly advised to consult a doctor immediately.\n"
            feedback += "🔹 Reduce sugar intake and follow a strict low-carb diet.\n"
            feedback += "🔹 Engage in daily physical activities such as walking or cardio exercises.\n"
        elif risk_level == "Moderate Risk (Pre-Diabetes)":
            feedback += "⚠️ Your results indicate MODERATE risk (Pre-Diabetes). You need to take preventive actions.\n"
            feedback += "🔹 Maintain a healthy weight and monitor your HbA1c levels regularly.\n"
            feedback += "🔹 Consider lifestyle changes, including a fiber-rich diet and exercise.\n"
        else:
            feedback += "✅ Your risk level is LOW. Keep maintaining a healthy lifestyle.\n"
            feedback += "🔹 Continue a balanced diet and engage in regular exercise.\n"

        # ✅ Health Recommendations
        recommendations = [
            "✅ Follow a diet rich in vegetables, lean proteins, and whole grains.",
            "✅ Engage in at least 30 minutes of physical activity daily.",
            "✅ Avoid sugary drinks and processed foods.",
            "✅ Maintain a consistent sleep schedule.",
            "✅ Regularly monitor your HbA1c and glucose levels."
        ]

        # ✅ Create PDF
        pdf_path = "current_prediction_report.pdf"
        pdf = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter

        # ✅ Add Title
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, height - 50, "Diabetes Prediction Report")

        # ✅ User Details Section
        pdf.setFont("Helvetica", 12)
        pdf.drawString(50, height - 80, f"User: {user_name}")
        pdf.drawString(50, height - 100, f"Age: {age}")
        pdf.drawString(50, height - 120, f"BMI: {bmi}")
        pdf.drawString(50, height - 140, f"Smoking History: {smoking_history}")

        # ✅ Prediction & Risk Level
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, height - 170, f"Prediction: {prediction}")
        pdf.setFillColorRGB(1, 0, 0) if risk_level == "High Risk" else pdf.setFillColorRGB(1, 0.5,
                                                                                           0) if risk_level == "Moderate Risk (Pre-Diabetes)" else pdf.setFillColorRGB(
            0, 1, 0)
        pdf.drawString(50, height - 190, f"Risk Level: {risk_level}")
        pdf.setFillColorRGB(0, 0, 0)  # Reset text color

        # ✅ Personalized Feedback
        pdf.setFont("Helvetica", 12)
        pdf.drawString(50, height - 220, "Personalized Feedback:")
        pdf.setFont("Helvetica-Oblique", 12)
        feedback_lines = feedback.split("\n")
        y_position = height - 240
        for line in feedback_lines:
            pdf.drawString(50, y_position, line)
            y_position -= 20

        # ✅ Health Recommendations
        pdf.setFont("Helvetica", 12)
        pdf.drawString(50, y_position - 20, "Recommended Actions:")
        y_position -= 40
        for rec in recommendations:
            pdf.drawString(50, y_position, rec)
            y_position -= 20

        # ✅ Save and return PDF file
        pdf.save()
        return send_file(pdf_path, as_attachment=True)

    except Exception as e:
        return f"Error generating PDF: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True
