# Dumper: Flask Machine Learning Application

## Overview

Dumper is a Flask web application that seamlessly integrates machine learning functionality for predictions and real-time network traffic analysis. Users can upload machine learning models, datasets, and perform predictions using the models. The application also provides a live display of network traffic analysis through WebSocket communication.

## Features

- User authentication (login, logout, registration)
- Upload and manage machine learning models
- Upload datasets for predictions
- Real-time network traffic analysis
- Dark mode for improved user experience

## Prerequisites

- Python 3.x
- Pip (Python package installer)
- Virtual environment (Optional but recommended)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/CS/dumper.git
    ```

2. Navigate to the project directory:

    ```bash
    cd dumper
    ```

3. Create a virtual environment (optional but recommended):

    ```bash
    python -m venv venv
    ```

4. Activate the virtual environment:

    - On Windows:

        ```bash
        venv\Scripts\activate
        ```

    - On macOS/Linux:

        ```bash
        source venv/bin/activate
        ```

5. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the Flask application:

    ```bash
    python app.py
    ```

2. Open your web browser and go to `http://127.0.0.1:5000/` to access the application.

3. If you are a new user, register an account. Otherwise, log in.

4. Use the navigation links to perform different actions:
    - **Predict**: Make predictions using uploaded machine learning models.
    - **Upload Model**: Upload and manage machine learning models.
    - **Upload Dataset**: Upload datasets for predictions.
    - **Network Traffic**: View real-time network traffic analysis.

5. Log out when you're done:

    ```bash
    deactivate  # If using a virtual environment
    ```

## Project Structure

- `app.py`: Main application file.
- `templates/`: HTML templates for rendering pages.
- `static/`: Static files like CSS styles and images.
- `user_models/`: Directory to store uploaded machine learning models.
- `venv/`: Virtual environment directory (created if using a virtual environment).

## Technologies Used

- Flask
- Flask-Login
- Flask-SocketIO
- Flask-WTF
- scapy
- Bootstrap (for styling)

## Contributors

- Your Name
- Additional contributors (if any)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
