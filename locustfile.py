from locust import HttpUser, task, between
from faker import Faker
import random
from datetime import date, timedelta

fake = Faker()

# Replace with your admin credentials
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "adminpassword"

class WebsiteUser(HttpUser):
    wait_time = between(1, 3)
    admin_logged_in = False
    admin_cookies = None

    @task
    def register_user(self):
        # Random mess cut: minimum 3 days
        mess_days = random.randint(3, 7)
        mess_start = date.today()
        mess_end = mess_start + timedelta(days=mess_days)

        user_data = {
            "name": fake.name(),
            "email": fake.unique.email(),
            "phone": str(fake.random_number(digits=10, fix_len=True)),
            "course": fake.word(),
            "password": "Password123",
            "user_type": "outmess",
            "mess_cut_start": mess_start.isoformat(),
            "mess_cut_end": mess_end.isoformat()
        }

        # Register user
        with self.client.post("/register", data=user_data, catch_response=True) as response:
            if "successfully registered" in response.text.lower():
                response.success()
                print(f"✅ Registered: {user_data['email']}")
                # Attempt admin approval
                self.approve_user(user_data["email"])
            else:
                response.failure(f"⚠️ Registration failed: {response.text}")

    def approve_user(self, user_email):
        # Login admin if not already
        if not self.admin_logged_in:
            admin_data = {
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD
            }
            with self.client.post("/login", data=admin_data, catch_response=True) as resp:
                if "dashboard" in resp.text.lower() or resp.status_code == 200:
                    self.admin_logged_in = True
                    self.admin_cookies = resp.cookies
                    resp.success()
                    print("✅ Admin logged in")
                else:
                    resp.failure("⚠️ Admin login failed")
                    return

        # Approve the user (replace with your actual endpoint)
        approve_data = {"email": user_email}
        with self.client.post("/admin/approve_user", data=approve_data, cookies=self.admin_cookies, catch_response=True) as resp:
            if resp.status_code == 200 and "approved" in resp.text.lower():
                resp.success()
                print(f"✅ Approved: {user_email}")
            else:
                resp.failure(f"⚠️ Approval failed: {resp.text}")
