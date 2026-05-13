"""
Run once to populate the users table with bcrypt-hashed passwords.
Usage: python seed_users.py
"""
import bcrypt
import db


def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


USERS = [
    {
        'username': 'admin',
        'password': 'admin123',
        'role': 'admin',
        'full_name': 'Faisal Sanad'
    },
    {
        'username': 'viewer',
        'password': 'viewer123',
        'role': 'viewer',
        'full_name': 'Read Only User'
    },
]

if __name__ == '__main__':
    for user in USERS:
        password_hash = hash_password(user['password'])
        db.execute("""
            INSERT INTO users (username, password_hash, role, full_name)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username) DO UPDATE
                SET password_hash = EXCLUDED.password_hash,
                    role = EXCLUDED.role,
                    full_name = EXCLUDED.full_name
        """, (user['username'], password_hash, user['role'], user['full_name']))
        print(f"  Seeded user: {user['username']} (role: {user['role']})")

    print("\n  Done. Users table updated with bcrypt-hashed passwords.")
