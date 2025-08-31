from locust import HttpUser, TaskSet, task, between
from faker import Faker
from datetime import datetime, timedelta
import random

fake = Faker()

class UserBehavior(TaskSet):
    def on_start(self):
        # Admin credentials
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"
        self.admin_logged_in = False
        self.admin_cookies = None
        self.new_users = []

        # Try to login as admin once
        self.login_admin()

    def login_admin(self):
        resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password
        }, allow_redirects=True)
        
        if resp.status_code == 200 and "dashboard" in resp.text.lower():
            self.admin_logged_in = True
            self.admin_cookies = resp.cookies
            print("✅ Admin login successful")
        else:
            print("⚠️ Admin login failed")

    @task
    def register_and_approve(self):
        # Step 1: Register random user
        name = fake.name()
        email = fake.unique.email()
        phone = "".join([str(random.randint(0, 9)) for _ in range(10)])
        course = random.choice(["DCS", "SMS", "MBA"])
        password = "password123"
        user_type = "outmess"

        response = self.client.post("/register", data={
            "name": name,
            "email": email,
            "phone": phone,
            "course": course,
            "password": password,
            "user_type": user_type
        }, allow_redirects=True)

        if response.status_code == 200:
            self.new_users.append(email)
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed for {email}")
            return

        if not self.admin_logged_in:
            print("⚠️ Admin not logged in, skipping approval")
            return

        # Step 2: Approve user
        for u_email in self.new_users:
            approve_resp = self.client.post("/admin/approve_bulk",
                json={"emails": [u_email]},
                headers={"Content-Type": "application/json"},
                cookies=self.admin_cookies
            )
            if approve_resp.status_code == 200:
                print(f"✅ Approved: {u_email}")
            else:
                print(f"❌ Failed to approve: {u_email}")

        # Step 3: Apply random mess cut (min 3 days)
        for u_email in self.new_users:
            start_date = datetime.today() + timedelta(days=random.randint(1, 10))
            end_date = start_date + timedelta(days=random.randint(3, 7))

            self.client.post("/apply_mess_cut", data={
                "start_date": start_date.strftime("%Y-%m-%d"),
                "end_date": end_date.strftime("%Y-%m-%d")
            }, cookies=self.admin_cookies)
            print(f"✅ Applied mess cut for {u_email} from {start_date.date()} to {end_date.date()}")

        # Clear new users for next task run
        self.new_users.clear()


class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 5)
