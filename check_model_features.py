import joblib

# Load the trained model
model = joblib.load("model.pkl")  # Make sure the path is correct

# Print the expected number of features
print("Model expects", model.n_features_in_, "features as input.")

# Try to retrieve feature names (if stored in the model)
if hasattr(model, "feature_names_in_"):
    print("Feature names used for training:", list(model.feature_names_in_))
else:
    print("Feature names are not stored in the model.")
