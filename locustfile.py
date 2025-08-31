from locust import HttpUser, task, between
import csv
import random

# ---------------- Load users from CSV ----------------
users = []
with open("test_users.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        users.append({
            "email": row["email"],
            "password": row["password"]
        })

# ---------------- Random details ----------------
def random_name():
    first = ["John","Jane","Alice","Bob","Charlie","Diana"]
    last = ["Smith","Doe","Brown","Johnson","Lee","Taylor"]
    return random.choice(first)+" "+random.choice(last)

def random_phone():
    return "".join(str(random.randint(0,9)) for _ in range(10))

def random_course():
    return random.choice(["DCS","SMS","BCA","MCA"])

# ---------------- Locust class ----------------
class MessAppUser(HttpUser):
    wait_time = between(0.05, 0.2)  # tiny wait for high load

    @task
    def register_and_bulk_approve(self):
        # Pick a random CSV user
        user = random.choice(users)

        # 1️⃣ Register user
        self.client.post("/register", data={
            "name": random_name(),
            "email": user["email"],
            "phone": random_phone(),
            "course": random_course(),
            "password": user["password"],
            "user_type": "student"
        })

        # 2️⃣ Bulk approve user (server must implement /admin/approve_bulk)
        self.client.post("/admin/approve_bulk", json={
            "emails": [user["email"]]  # can send a batch of emails
        })
