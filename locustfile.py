# locustfile.py
import csv
import random
from locust import HttpUser, task, between

# Load test users from CSV
users = []
with open("test_users.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        users.append({"email": row["email"], "password": row["password"]})

# Random names and courses for registration
names = ["Alice", "Bob", "Charlie", "David", "Eve"]
courses = ["DCS", "SMS", "BCA", "MCA", "EEE"]

class MessAppUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        # Pick a random user
        self.user_data = random.choice(users)
        self.email = self.user_data["email"]
        self.password = self.user_data["password"]

        # Register user
        reg_data = {
            "name": random.choice(names),
            "email": self.email,
            "course": random.choice(courses),
            "phone": f"{random.randint(6000000000, 9999999999)}",
            "password": self.password,
            "user_type": "student"
        }
        with self.client.post("/register", data=reg_data, catch_response=True) as response:
            if response.status_code == 302:  # redirects to login
                response.success()
            else:
                response.failure(f"Register failed: {response.text}")

        # Approve user via admin bulk API
        admin_login = {"email": "siberiamess4@gmail.com", "password": "siberia@123"}
        with self.client.post("/login", data=admin_login, catch_response=True) as resp:
            if resp.status_code == 302:
                resp.success()
            else:
                resp.failure(f"Admin login failed: {resp.text}")

        with self.client.post("/admin/approve_bulk", json={"emails": [self.email]}, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Approval failed: {resp.text}")

        # Login as student
        login_data = {"email": self.email, "password": self.password}
        with self.client.post("/login", data=login_data, catch_response=True) as resp:
            if resp.status_code == 302:
                resp.success()
            else:
                resp.failure(f"Student login failed: {resp.text}")

    @task
    def apply_mess_cut(self):
        from datetime import date, timedelta
        today = date.today()
        start = today + timedelta(days=2)
        end = start + timedelta(days=3)
        cut_data = {
            "start_date": start.isoformat(),
            "end_date": end.isoformat()
        }
        with self.client.post("/apply_mess_cut", data=cut_data, catch_response=True) as resp:
            if resp.status_code == 302:
                resp.success()
            else:
                resp.failure(f"Mess cut failed: {resp.text}")
