from locust import HttpUser, TaskSet, task, between
from datetime import datetime, timedelta
import random
import string

# ---------------- HELPER FUNCTIONS ----------------
def random_string(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))

def random_email():
    return f"{random_string(6)}@example.com"

# ---------------- TASKS ----------------
class UserBehavior(TaskSet):

    def on_start(self):
        # Login as admin once per Locust user to approve
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"
        self.login_admin()

    def login_admin(self):
        self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password
        })

    @task
    def register_approve_mess_cut(self):
        # 1️⃣ Register new user
        name = random_string()
        email = random_email()
        phone = ''.join(random.choices(string.digits, k=10))
        course = random.choice(["DCS", "SMS", "Other"])
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

        # 2️⃣ Approve user
        # Using API: fetch new_users list
        resp = self.client.get("/new_users")
        import re
        match = re.search(r'/approve_user/(\d+)"[^>]*>' + re.escape(email), resp.text)
        if match:
            user_id = match.group(1)
            self.client.get(f"/approve_user/{user_id}")

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
