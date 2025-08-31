# locustfile.py
import csv
import random
from locust import HttpUser, task, between

# Load users from CSV
users = []
with open("test_users.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        users.append({"email": row["email"], "password": row["password"]})

# Random extra details for registration
names = ["Alice", "Bob", "Charlie", "David", "Eve"]
courses = ["DCS", "SMS", "BCA", "MCA", "EEE"]

class MessAppUser(HttpUser):
    wait_time = between(1, 3)  # seconds between tasks

    def on_start(self):
        # Pick a random user from CSV
        self.user_data = random.choice(users)
        self.email = self.user_data["email"]
        self.password = self.user_data["password"]

        # 1️⃣ Register user
        reg_data = {
            "name": random.choice(names),
            "email": self.email,
            "course": random.choice(courses),
            "phone": f"{random.randint(6000000000, 9999999999)}",
            "password": self.password,
            "user_type": "student"
        }
        with self.client.post("/register", data=reg_data, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Register failed: {response.text}")

        # 2️⃣ Auto approve user via admin endpoint
        # WARNING: this assumes admin session already exists with cookie
        # Here we login as admin first
        admin_login = {
            "email": "siberiamess4@gmail.com",
            "password": "siberia@123"
        }
        with self.client.post("/login", data=admin_login, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Admin login failed: {resp.text}")

        # Fetch user ID from /new_users (simplest way for Locust, assuming small user list)
        new_users_resp = self.client.get("/new_users", catch_response=True)
        if new_users_resp.status_code == 200:
            # naive parsing: find user_id in HTML
            import re
            match = re.search(rf'/approve_user/(\d+).*?{self.email}', new_users_resp.text)
            if match:
                user_id = match.group(1)
                # Approve user
                self.client.get(f"/approve_user/{user_id}", catch_response=True)
        else:
            print("Failed to fetch new_users page")

        # 3️⃣ Login as student
        login_data = {
            "email": self.email,
            "password": self.password
        }
        with self.client.post("/login", data=login_data, catch_response=True) as login_resp:
            if login_resp.status_code == 200:
                login_resp.success()
            else:
                login_resp.failure(f"Student login failed: {login_resp.text}")

    @task
    def apply_mess_cut_task(self):
        import datetime
        today = datetime.date.today()
        start = today + datetime.timedelta(days=2)
        end = start + datetime.timedelta(days=3)
        cut_data = {
            "start_date": start.isoformat(),
            "end_date": end.isoformat()
        }
        with self.client.post("/apply_mess_cut", data=cut_data, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Mess cut failed: {resp.text}")
