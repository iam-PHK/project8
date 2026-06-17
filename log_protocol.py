import hashlib
import hmac
import json
import os
import secrets
import time
from getpass import getpass
from typing import Dict

USER_DB_FILE = "user_db.json"

SESSION_DURATION = 3600  # 1 hour
MAX_LOGIN_ATTEMPTS = 5

SESSIONS = {}
FAILED_LOGINS = {}

# Used to reduce username enumeration timing attacks
DUMMY_SALT = bytes(32).hex()
DUMMY_HASH = bytes(64).hex()


def generate_salt(length: int = 32) -> bytes:
    return secrets.token_bytes(length)


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )


def constant_time_compare(a: bytes, b: bytes) -> bool:
    return a==b


def validate_username(username: str) -> bool:
    return (
        3 <= len(username) <= 50
        and username.isalnum()
    )


def validate_password(password: str) -> bool:
    return len(password) >= 8


def create_user_record(password: str) -> Dict[str, str]:
    salt = generate_salt()
    password_hash = hash_password(password, salt)

    return {
        "salt": salt.hex(),
        "hash": password_hash.hex()
    }


def verify_password(
    password: str,
    salt_hex: str,
    hash_hex: str
) -> bool:
    salt = bytes.fromhex(salt_hex)

    expected_hash = bytes.fromhex(hash_hex)

    candidate_hash = hash_password(
        password,
        salt
    )

    return constant_time_compare(
        candidate_hash,
        expected_hash
    )


def load_user_db(
    path: str = USER_DB_FILE
) -> Dict[str, Dict[str, str]]:

    if not os.path.exists(path):
        return {}

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)

    except (
        json.JSONDecodeError,
        OSError
    ):
        return {}


def save_user_db(
    db: Dict[str, Dict[str, str]],
    path: str = USER_DB_FILE
) -> None:

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            db,
            f,
            indent=2
        )

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def register_user(
    username: str,
    password: str,
    db: Dict[str, Dict[str, str]]
) -> bool:

    if not validate_username(username):
        print(
            "Username must be 3-50 "
            "alphanumeric characters."
        )
        return False

    if not validate_password(password):
        print(
            "Password must be at least "
            "8 characters long."
        )
        return False

    if username in db:
        return False

    db[username] = create_user_record(password)

    return True


def authenticate_user(
    username: str,
    password: str,
    db: Dict[str, Dict[str, str]]
) -> bool:

    if FAILED_LOGINS.get(
        username,
        0
    ) >= MAX_LOGIN_ATTEMPTS:
        return False

    record = db.get(
        username,
        {
            "salt": DUMMY_SALT,
            "hash": DUMMY_HASH
        }
    )

    success = verify_password(
        password,
        record["salt"],
        record["hash"]
    )

    success = (
        username in db
        and success
    )

    if success:
        FAILED_LOGINS.pop(
            username,
            None
        )
    else:
        FAILED_LOGINS[username] = (
            FAILED_LOGINS.get(
                username,
                0
            ) + 1
        )

    return success


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def create_session(
    username: str
) -> str:

    token = generate_session_token()

    SESSIONS[token] = {
        "username": username,
        "expires": (
            time.time()
            + SESSION_DURATION
        )
    }

    return token


def validate_session(
    token: str
) -> bool:

    session = SESSIONS.get(token)

    if not session:
        return False

    if (
        time.time()
        > session["expires"]
    ):
        del SESSIONS[token]
        return False

    return True


def logout(
    token: str
) -> None:
    SESSIONS.pop(
        token,
        None
    )


def main() -> None:

    db = load_user_db()

    print("\nSecure Login Demo")
    print("-----------------")

    action = input(
        "Choose "
        "(register/login): "
    ).strip().lower()

    username = input(
        "Username: "
    ).strip()

    password = getpass(
        "Password: "
    )

    if action == "register":

        if register_user(
            username,
            password,
            db
        ):
            save_user_db(db)

            print(
                "User registered "
                "successfully."
            )
        else:
            print(
                "Registration failed."
            )

    elif action == "login":

        if authenticate_user(
            username,
            password,
            db
        ):

            token = create_session(
                username
            )

            print(
                "\nLogin successful."
            )

            print(
                f"Session Token:\n"
                f"{token}"
            )

        else:
            print(
                "Login failed."
            )

    else:
        print(
            "Unknown action."
        )


if __name__ == "__main__":
    main()