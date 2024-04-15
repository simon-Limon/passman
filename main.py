###### Imports ######
from fastapi import FastAPI, status, Depends, Cookie, Path, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
import pyodbc
import bcrypt
import jwt
import os
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
###### Imports ######


# Retrieving environmental variables for SQL Connection and token secret
sqlConnect = os.environ.get("sqlConnect")
tokenSecret = os.environ.get("tokenSecret")

# Defines the fastAPI app
app = FastAPI()

# Mounts the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Function to check for active user and retrieve userID and username
async def getActiveUser(accessToken: str = Cookie(None, alias='accessToken')):
    if accessToken is None:
        return None
    try:
        userData = jwt.decode(accessToken, tokenSecret, algorithms=["HS256"])
        if not userData:
            return None
        return userData
    except jwt.PyJWTError:
        return None

async def getMasterHash(userData: dict = Depends(getActiveUser)):
    userID = userData["userID"]
    with pyodbc.connect(sqlConnect) as dbConn:
        with dbConn.cursor() as cursor:
            cursor.execute("SELECT MasterHash FROM Users WHERE UserID = ?", userID)
            masterHash = cursor.fetchone()

    return masterHash[0]

def getEncryptionKey(userID: int, masterHash: str):
    # Retrieve the user's salt from the database
    with pyodbc.connect(sqlConnect) as dbConn:
        with dbConn.cursor() as cursor:
            cursor.execute("SELECT Salt FROM Users WHERE UserID = ?", userID)
            userSalt = cursor.fetchone()[0]
    
    # Generates an encryption key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=userSalt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(masterHash))  # Derive a key using the hash of the master password
    
    return key.decode()


# Root page end point
@app.get("/")
async def main(userData: dict = Depends(getActiveUser)):
    if userData:
        return RedirectResponse(f"/vault", status_code=status.HTTP_303_SEE_OTHER)
    return FileResponse("static/loginPage.html")


# Login endpoint
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    try:
        # Connects to the database
        with pyodbc.connect(sqlConnect) as dbConn:
                with dbConn.cursor() as cursor:
                    # Executes a query which selects the UserID and password hash for the given username
                    cursor.execute("SELECT UserID, MasterHash FROM Users WHERE MasterUsername = ?", username)
                    userData = cursor.fetchone() # Stores the data from the query in a dictionary
                    if not userData:
                        return RedirectResponse(url="/?code=401", status_code=status.HTTP_303_SEE_OTHER)
                    userID = userData[0]
                    masterHash = userData[1]
        # Checks the password against the stores hash for the user. If they match, a session token is created. A cookie containing the session token is then created.
        if bcrypt.checkpw(password.encode("utf-8"), masterHash):
            payload = {
                'userID': userID,
                'username': username
                }
            token = jwt.encode(
                payload,
                tokenSecret,
                algorithm="HS256"
                )
            response = RedirectResponse(f'/vault', status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                key="accessToken",
                value=token,
                samesite="Strict",
                secure=True,
                expires=60*60*24,
                domain=".voxu.gg",
                path="/",
                httponly=True
                )
            return response
        else:
            return RedirectResponse(url="/?code=401", status_code=status.HTTP_303_SEE_OTHER)
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/?code=500", status_code=status.HTTP_303_SEE_OTHER)



# Vault page endpoint
@app.get("/vault")
async def vaultPage(userData: dict = Depends(getActiveUser)):
    username = userData["username"]
    if username:
        return FileResponse("static/vault.html")
    else:
        return RedirectResponse("/")

# Register page endpoint
@app.get("/register")
async def registerPage():
        return FileResponse("static/registerPage.html")

# Logout endpoint
@app.post("/logout")
async def logout():
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(key="accessToken", path="/", domain=".voxu.gg", secure=True, samesite="Strict")
        return response


# Register endpoint
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), confirmPassword: str = Form(...)):

    # Checks if password meeths strength requirements
    if (len(password) < 12 or not re.search("[a-z]", password) or
        not re.search("[A-Z]", password) or not re.search("[!@#$%^&*(),.?\":{}|<>]", password)):
        return RedirectResponse(url="/register?code=422", status_code=status.HTTP_303_SEE_OTHER)
    if not password == confirmPassword:
        return RedirectResponse(url="/register?code=400", status_code=status.HTTP_303_SEE_OTHER)
    try:
        # Check if the username already exists
        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("SELECT 1 FROM Users WHERE MasterUsername = ?", username)
                if cursor.fetchone():
                    return RedirectResponse(url="/register?code=409", status_code=status.HTTP_303_SEE_OTHER)

        # Hashing the password, encodes it into binary, generates a salt and adds it to a variable called hash
        hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Generating another salt which is used to derive an encryption key
        salt = os.urandom(16)

        # Adding the username and the hashed password to the database
        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("INSERT INTO Users (MasterUsername, MasterHash, Salt) VALUES (?, ?, ?);", username, hash, salt)
                dbConn.commit()
    
    # Returns an error code if there is a problem with the server connection
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/register?code=500", status_code=status.HTTP_303_SEE_OTHER)
    
    # Redirects user to the login page with a success error code
    return RedirectResponse(url="/?code=201", status_code=status.HTTP_303_SEE_OTHER)


# Endpoint for adding entries to the vault
@app.post("/newVaultEntry")
async def newVaultEntry(serviceName: str = Form(...), serviceUsername: str = Form(...), servicePassword: str = Form(...), userData: dict = Depends(getActiveUser), masterHash: str = Depends(getMasterHash)):
    try:
        userID = userData["userID"]
        encryptionKey = getEncryptionKey(userID,masterHash)
        cipher = Fernet(encryptionKey)
        encryptedPassword = cipher.encrypt(servicePassword.encode("utf-8"))

        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("INSERT INTO Vaults (UserID, ServiceName, Username, EncryptedPassword) VALUES (?, ?, ?, ?);", userID, serviceName, serviceUsername, encryptedPassword)
                dbConn.commit()
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)
    
    return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/getVaultEntries")
async def getVaultEntries(userData: dict = Depends(getActiveUser), masterHash: str = Depends(getMasterHash)):
    if not userData:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        userID = userData["userID"]
        encryptionKey = getEncryptionKey(userID, masterHash)
        cipher = Fernet(encryptionKey)
        vaultEntries = []

        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("SELECT EntryID, ServiceName, Username, EncryptedPassword FROM Vaults WHERE UserID = ?", userID)
                for row in cursor.fetchall():
                    entryID, serviceName, serviceUsername, encryptedPassword = row
                    decryptedPassword = cipher.decrypt(encryptedPassword)
                    vaultEntries.append({
                        "entryID": entryID,
                        "serviceName": serviceName,
                        "serviceUsername": serviceUsername,
                        "servicePassword": decryptedPassword
                    })
        return vaultEntries
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)


@app.delete("/deleteVaultEntry/{entryID}")
async def deleteVaultEntry(entryID: int = Path(...), userData: dict = Depends(getActiveUser)):
    if not userData:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("DELETE FROM Vaults WHERE EntryID = ?;", entryID)
                dbConn.commit()
        return

    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/changePassword")
async def changePassword(oldPassword: str = Form(...), newPassword: str = Form(...), confirmPassword: str = Form(...), userData: dict = Depends(getActiveUser), masterHash: str = Depends(getMasterHash)):
    if not userData:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        userID = userData["userID"]

        # Checks if password meets requirements
        if (len(newPassword) < 12 or not re.search("[a-z]", newPassword) or
            not re.search("[A-Z]", newPassword) or not re.search("[!@#$%^&*(),.?\":{}|<>]", newPassword)):
            return RedirectResponse(url="/vault?code=422", status_code=status.HTTP_303_SEE_OTHER)
        if not newPassword == confirmPassword:
            return RedirectResponse(url="/vault?code=422", status_code=status.HTTP_303_SEE_OTHER)
        
        # Checks if the old password is correct
        if not bcrypt.checkpw(oldPassword.encode("utf-8"), masterHash):
            return RedirectResponse(url="/vault?code=422", status_code=status.HTTP_303_SEE_OTHER)
        
        oldHash = masterHash
        oldEncryptionKey = getEncryptionKey(userID, oldHash)
        oldCipher = Fernet(oldEncryptionKey)

        newHash = bcrypt.hashpw(newPassword.encode("utf-8"), bcrypt.gensalt())
        newEncryptionKey = getEncryptionKey(userID, newHash)
        newCipher = Fernet(newEncryptionKey)

        decryptedPasswords = []
        # Adding the new hashed password to the database
        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("UPDATE Users SET MasterHash = ? WHERE UserID = ?;", newHash, userID)
                dbConn.commit()
            
            with dbConn.cursor() as cursor:
                cursor.execute("SELECT EncryptedPassword FROM Vaults WHERE UserID = ?", userID)
                for row in cursor.fetchall():
                    encryptedPassword = row[0]
                    decryptedPassword = oldCipher.decrypt(encryptedPassword)
                    decryptedPasswords.append(decryptedPassword)
                
            with dbConn.cursor() as cursor:
                for decryptedPassword in decryptedPasswords:
                    encryptedPassword = newCipher.encrypt(decryptedPassword)
                    cursor.execute("UPDATE Vaults SET EncryptedPassword = ? WHERE UserID = ?", encryptedPassword, userID)
        
            return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)
    
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/vault", status_code=status.HTTP_303_SEE_OTHER)
    

@app.post("/deleteAccount")
async def deleteAccount(userData: dict = Depends(getActiveUser)):
    if not userData:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        userID = userData["userID"]
        with pyodbc.connect(sqlConnect) as dbConn:
            with dbConn.cursor() as cursor:
                cursor.execute("DELETE FROM Users WHERE UserID = ?", userID)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(key="accessToken", path="/", domain=".voxu.gg", secure=True, samesite="Strict")
        return response
    except pyodbc.Error as error:
        print(error)
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)