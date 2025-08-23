import os
import mysql.connector
from dotenv import load_dotenv

# Load .env file
load_dotenv()

try:
    connection = mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        port=os.getenv("MYSQLPORT"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE")
    )

    if connection.is_connected():
        print("✅ Successfully connected to Railway MySQL!")

except mysql.connector.Error as e:
    print("❌ Error while connecting:", e)
