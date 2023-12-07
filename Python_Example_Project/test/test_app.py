# # tests/test_app.py
# from app import app

# import pytest


# @pytest.fixture
# def client():
#     app.config['TESTING'] = True
#     with app.test_client() as client:
#         yield client


# def test_index_route(client):
#     response = client.get('/')
#     assert response.status_code == 302  # Should redirect to login page when not authenticated


# def test_login_route(client):
#     response = client.get('/login')
#     assert response.status_code == 200  # Should return login page


# def test_logout_route(client):
#     response = client.get('/logout')
#     assert response.status_code == 302  # Should redirect to login page after logout


# # Add more tests based on your routes and functionalities
