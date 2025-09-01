from locust import HttpUser, TaskSet, task, between
from faker import Faker
from datetime import datetime
import random
from bs4 import BeautifulSoup

fake = Faker()

class UserBehavior(TaskSet):
    def on_start(self):
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"

    def admin_login(self):
        # GET login page to fetch CSRF token
        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_token_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_token_input["value"] if csrf_token_input else ""

        # POST login with CSRF token
        login_resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password,
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if "Login successful" in login_resp.text or login_resp.status_code == 200:
            print("✅ Admin login successful")
            return True
        else:
            print("⚠️ Admin login failed")
            return False

    @task
    def register_approve_and_scan_qr(self):
        # Step 1: Register a single user
        name = fake.name()
        email = fake.unique.email()
        phone = "".join([str(random.randint(0, 9)) for _ in range(10)])
        course = random.choice(["DCS", "SMS", "MBA"])
        password = "password123"
        user_type = "outmess"

        resp = self.client.post("/register", data={
            "name": name,
            "email": email,
            "phone": phone,
            "course": course,
            "password": password,
            "user_type": user_type
        }, allow_redirects=True)

        if resp.status_code == 200:
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed: {email}")
            return

        # Step 2: Admin login
        if not self.admin_login():
            return

        # Step 3: Approve the user
        approve_resp = self.client.post("/admin/approve_bulk",
            json={"emails": [email]},
            headers={"Content-Type": "application/json"}
        )
        if approve_resp.status_code == 200:
            print(f"✅ Approved: {email}")
        else:
            print(f"❌ Failed to approve: {email}")
            return

        # Step 4: Scan QR for the user
        scan_resp = self.client.post("/scan_qr", data={
            "email": email,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        if scan_resp.status_code == 200:
            print(f"✅ QR scanned for {email}")
        else:
            print(f"❌ QR scan failed for {email}")


class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 5)
