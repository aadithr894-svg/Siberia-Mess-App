import random
from locust import HttpUser, task, between

names = ["Alice", "Bob", "Charlie", "David", "Eve"]
courses = ["DCS", "SMS", "BCA", "MCA", "EEE"]

class MessAppUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        # Unique email per Locust instance
        self.email = f"user{random.randint(10000,99999)}@test.com"
        self.password = "Password123"

        # 1️⃣ Register
        reg_data = {
            "name": random.choice(names),
            "email": self.email,
            "course": random.choice(courses),
            "phone": f"{random.randint(6000000000, 9999999999)}",
            "password": self.password,
            "user_type": "student"
        }
        self.client.post("/register", data=reg_data, allow_redirects=True)

        # 2️⃣ Login as admin to approve the new user
        admin_login = {"email": "siberiamess4@gmail.com", "password": "siberia@123"}
        self.client.post("/login", data=admin_login, allow_redirects=True)

        # Approve the newly registered user
        self.client.post("/admin/approve_bulk", json={"emails": [self.email]}, allow_redirects=True)

        # Logout admin
        self.client.get("/logout", allow_redirects=True)

        # 3️⃣ Login as student
        student_login = {"email": self.email, "password": self.password}
        self.client.post("/login", data=student_login, allow_redirects=True)

        # Flag for running mess cut only once
        self.mess_cut_done = False

    @task
    def apply_mess_cut_once(self):
        if self.mess_cut_done:
            return

        from datetime import date, timedelta
        today = date.today()
        start = today + timedelta(days=2)
        end = start + timedelta(days=3)

        cut_data = {
            "start_date": start.isoformat(),
            "end_date": end.isoformat()
        }

        self.client.post("/apply_mess_cut", data=cut_data, allow_redirects=True)
        self.mess_cut_done = True
