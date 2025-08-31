from locust import HttpUser, TaskSet, task, between
from datetime import datetime, timedelta
import random
import string
import json

# ---------------- HELPER FUNCTIONS ----------------
def random_string(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))

def random_email():
    return f"{random_string(6)}@example.com"

def random_phone():
    return ''.join(random.choices("0123456789", k=10))

def random_course():
    return random.choice(["DCS", "SMS", "Other"])

# ---------------- TASKS ----------------
class UserBehavior(TaskSet):

    def on_start(self):
        # Login as admin once per Locust user to approve users
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"
        self.login_admin()

    def login_admin(self):
        self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password
        })

    @task
    def register_and_autoapprove(self):
        # 1️⃣ Register a new user
        name = random_string()
        email = random_email()
        phone = random_phone()
        course = random_course()
        password = "user123"
        user_type = "outmess"

        self.client.post("/register", data={
            "name": name,
            "email": email,
            "phone": phone,
            "course": course,
            "password": password,
            "user_type": user_type
        })

        # 2️⃣ Auto approve using /approve_bulk endpoint
        self.client.post("/admin/approve_bulk", 
            json={"emails": [email]}
        )

        # 3️⃣ Apply random mess cut (min 3 days)
        today = datetime.now().date()
        start_date = today + timedelta(days=random.randint(1, 5))
        end_date = start_date + timedelta(days=random.randint(3, 7))

        self.client.post("/apply_mess_cut", data={
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
        })

# ---------------- LOCUST USER ----------------
class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 3)  # seconds between tasks
