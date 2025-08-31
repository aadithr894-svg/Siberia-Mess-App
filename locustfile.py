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
        self.new_users = []

    @task
    def register_and_approve(self):
        # Step 1: Register random user
        name = fake.name()
        email = fake.unique.email()
        phone = "".join([str(random.randint(0, 9)) for _ in range(10)])
        course = random.choice(["DCS", "SMS", "MBA"])
        password = "password123"
        user_type = "Outmess"  # Must match backend exactly

        # Register user
        response = self.client.post(
            "/register",
            data={
                "name": name,
                "email": email,
                "phone": phone,
                "course": course,
                "password": password,
                "user_type": user_type
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True
        )

        if response.status_code == 200 and "success" in response.text.lower():
            self.new_users.append(email)
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed: {email}")
            return  # Skip approval if registration fails

        # Step 2: Login as admin
        login_resp = self.client.post(
            "/login",
            data={"email": self.admin_email, "password": self.admin_password},
            allow_redirects=True
        )

        if "Login successful" not in login_resp.text:
            print("⚠️ Admin login failed")
            return

        # Step 3: Approve the new user(s)
        for u_email in self.new_users:
            approve_resp = self.client.post(
                "/admin/approve_bulk",
                json={"emails": [u_email]},
                headers={"Content-Type": "application/json"}
            )
            if approve_resp.status_code == 200:
                print(f"✅ Approved: {u_email}")
            else:
                print(f"❌ Failed to approve: {u_email}")

        # Step 4: Apply random mess cut (min 3 days)
        for u_email in self.new_users:
            start_date = datetime.today() + timedelta(days=random.randint(1, 10))
            end_date = start_date + timedelta(days=random.randint(3, 7))

            self.client.post(
                "/apply_mess_cut",
                data={
                    "email": u_email,  # Include email if backend requires
                    "start_date": start_date.strftime("%Y-%m-%d"),
                    "end_date": end_date.strftime("%Y-%m-%d")
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            print(f"✅ Applied mess cut for {u_email} from {start_date.date()} to {end_date.date()}")

        # Clear new users list for next iteration
        self.new_users.clear()

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 5)
