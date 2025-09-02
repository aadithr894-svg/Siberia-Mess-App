from locust import HttpUser, task, between
from faker import Faker
from bs4 import BeautifulSoup
import random

fake = Faker()

class WebsiteUser(HttpUser):
    wait_time = between(1, 3)

    admin_email = "siberiamess4@gmail.com"
    admin_password = "siberia@123"
    fixed_password = "admin123"

    @task
    def register_approve_login(self):
        # 1️⃣ Register new user
        name = fake.name()
        email = fake.unique.email()
        phone = "".join([str(random.randint(0, 9)) for _ in range(10)])
        course = random.choice(["DCS", "SMS", "MBA"])
        user_type = "outmess"

        reg_resp = self.client.post("/register", data={
            "name": name,
            "email": email,
            "phone": phone,
            "course": course,
            "password": self.fixed_password,
            "user_type": user_type
        }, allow_redirects=True)

        if reg_resp.status_code == 200:
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed: {email}")
            return

        # 2️⃣ Admin login to approve this user
        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_input["value"] if csrf_input else ""

        admin_login_resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password,
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if admin_login_resp.status_code == 200:
            print("✅ Admin logged in")
        else:
            print("❌ Admin login failed")
            return

        # Approve user
        approve_resp = self.client.post("/admin/approve_bulk",
                                        json={"emails": [email]},
                                        headers={"Content-Type": "application/json"})
        if approve_resp.status_code == 200:
            print(f"✅ Approved: {email}")
        else:
            print(f"❌ Approval failed: {email}")
            return

        # 3️⃣ User login with fixed password
        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_input["value"] if csrf_input else ""

        login_resp = self.client.post("/login", data={
            "email": email,
            "password": self.fixed_password,
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if login_resp.status_code == 200:
            print(f"✅ User logged in: {email}")
        else:
            print(f"❌ User login failed: {email}")
