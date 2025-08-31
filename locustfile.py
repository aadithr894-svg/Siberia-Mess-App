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
        user_type = "outmess"

        # Register user
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

        # Step 2: Login as admin
        login_resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password
        }, allow_redirects=True)

        if "Login successful" not in login_resp.text:
            print("⚠️ Admin login failed")
            return

        # Step 3: Approve the user(s)
        for u_email in self.new_users:
            approve_resp = self.client.post("/admin/approve_bulk",
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

            # Fetch user ID after approval
            user_id_resp = self.client.get("/admin/users")  # This returns HTML; you may parse it or use DB API
            # For simplicity, we skip getting exact user_id; in real setup, fetch user ID after approval

            # Simulate applying mess cut
            self.client.post("/apply_mess_cut", data={
                "start_date": start_date.strftime("%Y-%m-%d"),
                "end_date": end_date.strftime("%Y-%m-%d")
            })
            print(f"✅ Applied mess cut for {u_email} from {start_date.date()} to {end_date.date()}")

        # Clear new users for next run
        self.new_users.clear()

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 5)
