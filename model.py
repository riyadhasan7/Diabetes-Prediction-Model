import pickle

import pandas as pd
import numpy as np

# Ensure the correct file path
df = pd.read_csv("diabetes_prediction_dataset.csv")

# Print the first few rows of the DataFrame
print(df.head())


print(df.shape)

print(df.info())

print(df.describe())


# Fix data types
# Convert 'gender', 'smoking_history', 'diabetes' to categorical
for col in ['gender', 'smoking_history', 'diabetes','heart_disease','smoking_history','hypertension']:
    df[col] = df[col].astype('category')

# Convert 'age' to integer
df['age'] = df['age'].astype('int')

# Verify the changes
print(df.info())


# Separate numerical and categorical columns
numerical_cols = df.select_dtypes(include=['number']).columns
categorical_cols = df.select_dtypes(include=['category']).columns

print("Numerical columns:", numerical_cols)
print("Categorical columns:", categorical_cols)


import matplotlib.pyplot as plt
import seaborn as sns


# Check for duplicates
duplicates = df[df.duplicated()]
print("Number of duplicate rows:", len(duplicates))

# Remove duplicates (inplace modification)
df.drop_duplicates(inplace=True)

# Verify the removal
print("Number of rows after removing duplicates:", len(df))



def find_outliers_iqr(df, column):
    Q1 = df[column].quantile(0.25)
    Q3 = df[column].quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    outliers = df[(df[column] < lower_bound) | (df[column] > upper_bound)]
    return outliers

# Example usage for all numerical columns:
for col in numerical_cols:
  outliers = find_outliers_iqr(df, col)
  print(f"Outliers in {col}:\n{outliers[[col]]}\n")


def find_outliers_zscore(df, column, threshold=3):
    z_scores = np.abs((df[column] - df[column].mean()) / df[column].std())
    outliers = df[z_scores > threshold]
    return outliers

# Example usage for all numerical columns
for col in numerical_cols:
    outliers = find_outliers_zscore(df, col)
    print(f"Outliers in {col} (Z-score method):\n{outliers[[col]]}\n")




# Create the pie chart
plt.figure(figsize=(8, 8))
df['diabetes'].value_counts().plot.pie(autopct='%1.1f%%', startangle=90)
plt.title('Distribution of Diabetes')
plt.ylabel('')  # Remove the y-label
plt.show()




from imblearn.over_sampling import SMOTE
import pandas as pd
import matplotlib.pyplot as plt

# Assuming df and other necessary objects are already defined from the previous code

# Separate features (X) and target variable (y)
X = df.drop('diabetes', axis=1)
y = df['diabetes']

# Convert categorical features to numerical using one-hot encoding
X = pd.get_dummies(X, columns=['gender', 'smoking_history', 'heart_disease','hypertension'])

# Apply SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Create a new DataFrame with the resampled data
df_resampled = pd.DataFrame(X_resampled, columns=X.columns)
df_resampled['diabetes'] = y_resampled

# Visualize the balanced target variable using a pie chart
plt.figure(figsize=(8, 8))
df_resampled['diabetes'].value_counts().plot.pie(autopct='%1.1f%%', startangle=90)
plt.title('Distribution of Diabetes (After SMOTE)')
plt.ylabel('')  # Remove the y-label
plt.show()







from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Split the resampled data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.2, random_state=42
)

# Initialize the Random Forest Classifier
rf_classifier = RandomForestClassifier(random_state=42, n_estimators=100)

# Train the classifier on the training set
rf_classifier.fit(X_train, y_train)

# Make a pickle file for our model
pickle.dump(rf_classifier, open("model.pkl", "wb"))

# Predict on the test set
y_pred = rf_classifier.predict(X_test)

# Evaluate the classifier's performance
print("Accuracy on Test Set:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Perform 5-fold cross-validation and print the average accuracy
cv_scores = cross_val_score(rf_classifier, X_resampled, y_resampled, cv=5)
print("\nAverage Cross-Validation Accuracy: {:.2f}%".format(cv_scores.mean() * 100))