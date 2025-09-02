from locust import HttpUser, TaskSet, task, between
from faker import Faker
from bs4 import BeautifulSoup
import random

fake = Faker()
registered_users = []

class UserRegistration(TaskSet):
    def on_start(self):
        # Fixed password for all users
        self.password = "admin123"

    @task
    def register_user(self):
        name = fake.name()
        email = fake.unique.email()
        phone = "".join([str(random.randint(0, 9)) for _ in range(10)])
        course = random.choice(["DCS", "SMS", "MBA"])
        user_type = "outmess"

        resp = self.client.post("/register", data={
            "name": name,
            "email": email,
            "phone": phone,
            "course": course,
            "password": self.password,
            "user_type": user_type,
        
            "food_type":food_type
        }, allow_redirects=True)

        if resp.status_code == 200:
            print(f"✅ Registered: {email}")
            registered_users.append({"email": email, "password": self.password})
        else:
            print(f"❌ Registration failed: {email}")


class AdminApproval(TaskSet):
    def on_start(self):
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"
        self.login_admin()

    def login_admin(self):
        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_input["value"] if csrf_input else ""

        login_resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password,
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if login_resp.status_code == 200:
            print("✅ Admin logged in")
        else:
            print("❌ Admin login failed")

    @task
    def approve_all(self):
        if registered_users:
            emails_to_approve = [u["email"] for u in registered_users]
            resp = self.client.post("/admin/approve_bulk",
                                    json={"emails": emails_to_approve},
                                    headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                print(f"✅ Approved {len(emails_to_approve)} users")
            else:
                print("❌ Approval failed")


class UserLogin(TaskSet):
    def on_start(self):
        if registered_users:
            self.user = registered_users.pop(0)
        else:
            self.user = None

    @task
    def login(self):
        if not self.user:
            return

        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_input["value"] if csrf_input else ""

        login_resp = self.client.post("/login", data={
            "email": self.user["email"],
            "password": self.user["password"],
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if login_resp.status_code == 200:
            print(f"✅ User logged in: {self.user['email']}")
        else:
            print(f"❌ Login failed: {self.user['email']}")


class WebsiteUser(HttpUser):
    tasks = [UserRegistration]
    wait_time = between(1, 3)


class AdminUser(HttpUser):
    tasks = [AdminApproval]
    wait_time = between(5, 10)


class RegisteredUser(HttpUser):
    tasks = [UserLogin]
    wait_time = between(1, 2)
