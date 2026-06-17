def get_active_users(users):
    active_users = []

    for user in users:
        if user["last_login_days"] < 30:
            active_users.append(user)

    return active_users