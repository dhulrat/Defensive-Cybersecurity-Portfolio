ROLES = {
    "Admin": ["read", "write", "delete", "manage_users"],
    "Editor": ["read", "write"],
    "Viewer": ["read"]
}

USERS = {
    "alice": {"username": "alice", "role": "Admin"},
    "ben": {"username": "ben", "role": "Editor"},
    "chris": {"username": "chris", "role": "Viewer"}
}


def require_permission(action):
    def decorator(func):
        def wrapper(user, *args, **kwargs):
            role = user["role"]

            if action in ROLES[role]:
                return func(user, *args, **kwargs)

            raise PermissionError(
                f"Access denied: {user['username']} does not have '{action}' permission."
            )

        return wrapper
    return decorator


@require_permission("read")
def read_file(user, filename):
    print(f"{user['username']} read the file: {filename}")


@require_permission("write")
def write_file(user, filename):
    print(f"{user['username']} edited the file: {filename}")


@require_permission("delete")
def delete_file(user, filename):
    print(f"{user['username']} deleted the file: {filename}")


@require_permission("manage_users")
def manage_users(user):
    print(f"{user['username']} managed user accounts.")


def test_rbac():
    users_to_test = [USERS["alice"], USERS["ben"], USERS["chris"]]

    for user in users_to_test:
        print(f"\nTesting user: {user['username']} | Role: {user['role']}")

        for action in [read_file, write_file, delete_file]:
            try:
                action(user, "example.txt")
            except PermissionError as error:
                print(error)

        try:
            manage_users(user)
        except PermissionError as error:
            print(error)


if __name__ == "__main__":
    test_rbac()