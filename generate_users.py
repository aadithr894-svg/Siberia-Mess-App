import csv

# Number of test users you want
num_users = 350
password = "testpass"  # common password for all test users

# Open CSV file for writing
with open("test_users.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    
    # Write header
    writer.writerow(["email", "password"])
    
    # Generate users
    for i in range(1, num_users + 1):
        email = f"user{i}@mail.com"
        writer.writerow([email, password])

print(f"CSV file 'test_users.csv' created with {num_users} users.")
