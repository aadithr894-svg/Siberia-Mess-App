import csv
import random
from locust import HttpUser, task, between

# ------------------ Load test users ------------------
USERS = []
with open("test_users.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        USERS.append(row)

# ------------------ Helper ------------------
def random_phone():
    return str(random.randint(6000000000, 9999999999))

def random_course():
    return random.choice(["DCS", "SMS", "MCA", "BSc"])

def random_user_type():
    return "student"

# ------------------ Locust User ------------------
class MessAppUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Pick a random test user
        self.user = random.choice(USERS)
        self.email = self.user["email"]
        self.password = self.user["password"]
        self.name = f"User_{random.randint(1000,9999)}"
        self.phone = random_phone()
        self.course = random_course()
        self.user_type = random_user_type()

        # 1️⃣ Register
        with self.client.post(
            "/register",
            data={
                "name": self.name,
                "email": self.email,
                "course": self.course,
                "phone": self.phone,
                "password": self.password,
                "user_type": self.user_type
            },
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Register failed: {response.text}")

        # 2️⃣ Auto-approve via admin endpoint
        # Assuming default admin exists with id=1
        # Fetch new_user id first
        new_user_id = None
        r = self.client.get("/new_users", catch_response=True)
        if r.status_code == 200:
            # crude extraction from HTML
            import re
            match = re.search(r"/approve_user/(\d+)", r.text)
            if match:
                new_user_id = match.group(1)
        
        if new_user_id:
            self.client.get(f"/approve_user/{new_user_id}", catch_response=True)
        
        # 3️⃣ Login
        with self.client.post(
            "/login",
            data={"email": self.email, "password": self.password},
            catch_response=True
        ) as response:
            if "Login successful!" in response.text:
                response.success()
            else:
                response.failure("Login failed")

    # ------------------ Example task ------------------
    @task
    def apply_mess_cut(self):
        from datetime import date, timedelta
        today = date.today()
        start_date = today + timedelta(days=2)
        end_date = start_date + timedelta(days=3)
        self.client.post(
            "/apply_mess_cut",
            data={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            catch_response=True
        )
