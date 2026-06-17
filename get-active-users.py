def get_active_users(users):
    """
    Returns a list of users who have been active within the last 30 days.

    Args:
        users (list[dict]): List of user dictionaries.

    Returns:
        list[dict]: Filtered list of active users.
    """

    active_users = []

    for user in users:
        # Safely extract 'last_login_days' to avoid KeyError
        last_login = user.get("last_login_days")

        # Skip users with missing login data
        if last_login is None:
            continue

        # Check if user is considered active (logged in within last 30 days)
        if last_login < 30:
            active_users.append(user)

    return active_users