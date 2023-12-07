# create_model.py

import joblib
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

# Generate synthetic dataset for demonstration
X, y = make_classification(
    n_samples=100, 
    n_features=2, 
    n_informative=2,
    n_redundant=0,
    n_classes=2, 
    random_state=42
)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create and train a simple Logistic Regression model
model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)

# Save the trained model to a file
joblib.dump(model, "model.pkl")
