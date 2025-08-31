from locust import HttpUser, TaskSet, task, between
from faker import Faker
from datetime import datetime, timedelta
import random
from bs4 import BeautifulSoup

fake = Faker()

class UserBehavior(TaskSet):
    def on_start(self):
        self.admin_email = "siberiamess4@gmail.com"
        self.admin_password = "siberia@123"
        self.new_users = []

    def admin_login(self):
        resp = self.client.get("/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_token_input = soup.find("input", {"name": "csrf_token"})
        csrf_token = csrf_token_input["value"] if csrf_token_input else ""

        login_resp = self.client.post("/login", data={
            "email": self.admin_email,
            "password": self.admin_password,
            "csrf_token": csrf_token
        }, allow_redirects=True)

        if login_resp.status_code == 200:
            print("✅ Admin login successful")
            return True
        else:
            print("⚠️ Admin login failed")
            return False

    @task
    def register_and_approve(self):
        # Step 1: Register random user
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
            self.new_users.append(email)
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed: {email}")
            return

        # Step 2: Admin login
        if not self.admin_login():
            return

        # Step 3: Approve users
        for u_email in self.new_users:
            approve_resp = self.client.post("/admin/approve_bulk",
                json={"emails": [u_email]},
                headers={"Content-Type": "application/json"}
            )
            if approve_resp.status_code == 200:
                print(f"✅ Approved: {u_email}")
            else:
                print(f"❌ Failed to approve: {u_email}")

        # Step 4: Fetch user IDs and apply random mess cuts
        users_resp = self.client.get("/admin/users")
        soup = BeautifulSoup(users_resp.text, "html.parser")
        # Assuming each user row has data-email and data-id attributes
        user_rows = soup.find_all("tr")
        user_id_map = {}
        for row in user_rows:
            email_td = row.find("td", {"data-email": True})
            id_td = row.find("td", {"data-id": True})
            if email_td and id_td:
                user_id_map[email_td["data-email"]] = id_td["data-id"]

        for u_email in self.new_users:
            user_id = user_id_map.get(u_email)
            if not user_id:
                print(f"❌ Could not fetch user ID for {u_email}")
                continue

            start_date = datetime.today() + timedelta(days=random.randint(1, 10))
            end_date = start_date + timedelta(days=random.randint(3, 7))

            self.client.post("/apply_mess_cut", data={
                "user_id": user_id,
                "start_date": start_date.strftime("%Y-%m-%d"),  # must be YYYY-MM-DD
                "end_date": end_date.strftime("%Y-%m-%d")
            })
            print(f"✅ Applied mess cut for {u_email} from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")

        self.new_users.clear()


class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 5)
