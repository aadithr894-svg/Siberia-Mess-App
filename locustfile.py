from locust import HttpUser, task, between
from faker import Faker

fake = Faker()

ADMIN_USERNAME = "siberiamess4@gmail.com"
ADMIN_PASSWORD = "siberia@123"

class WebsiteUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def register_and_approve(self):
        # --- Step 1: Register user ---
        email = fake.email()
        password = "Password123"  # use a default password
        user_data = {
            "name": fake.name(),
            "email": email,
            "password": password,
            "user_type": "outmess"
        }
        response = self.client.post("/register", data=user_data)
        if response.status_code == 200:
            print(f"✅ Registered: {email}")
        else:
            print(f"❌ Registration failed: {email}")
            return

        # --- Step 2: Admin login ---
        admin_data = {
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
        admin_response = self.client.post("/admin/login", data=admin_data)
        if admin_response.status_code != 200:
            print("⚠️ Admin login failed")
            return
        print("✅ Admin logged in")

        # --- Step 3: Approve user ---
        approve_data = {"email": email}  # Adjust field based on your API
        approve_response = self.client.post("/admin/approve_user", data=approve_data)
        if approve_response.status_code == 200:
            print(f"✅ Approved: {email}")
        else:
            print(f"❌ Approval failed: {email}")
