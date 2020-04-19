1. make sure that you have a copy of Python 3.8
2. Download the project code
3. In a terminal window, navigate into the project directory and run pip install -r requirements.txt
4. Set the environment variable FLASK_APP to be application.py. On a Mac or on Linux, the command to do this is export FLASK_APP=application.py. On Windows, the command is set FLASK_APP=application.py.
5. Run flask run to start up your Flask application

to create a new admin: 
curl -H "Content-Type: application/json" -d "{ \\"username\\": \\"{username}\\", \\"password\\": \\"{password}\\"}" http://127.0.0.1:5000/v1/register

to create users in tenant:
curl --user {admin_username}:{password} -H "Content-Type: application/json" -d "{ \\"username\\": \\"{username}\\", \\"password\\": \\"{password}\\"}" http://127.0.0.1:5000/v1/{tenant}/users 

to see all users in tenant:
curl --user {username}:{password} http://127.0.0.1:5000/v1/{tenant}/users 

to see the requesting user info:
curl --user {username}:{password} http://127.0.0.1:5000/v1/{tenant}/users/me

to delete a user:
curl --user {admin_username}:{password} --request DELETE http://127.0.0.1:5000/v1/{tenant}/users/{userid} 

to send a message:
curl --user {sender_username}:{password} -H "Content-Type: application/json" -d "{\\"body\\": \\"{message}\\"}" http://127.0.0.1:5000/v1/{tenant}/users/{userid}/encrypt

to read an encrypted message:
curl --user {username}:{password} -H "Content-Type: application/json" -d "{\\"body\\": \\"{encrypted_message}\\"}" http://127.0.0.1:5000/v1/{tenant}/users/me/decrypt

sing in to http://127.0.0.1:5000 at any time to do all of the above actions!