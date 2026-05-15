using BCrypt.Net;

namespace IBLabProject
{
    public static class PasswordHasher
    {
        // Hashes the password with bcrypt (includes random salt)
        public static string Hash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        // Verifies a plain password against a stored bcrypt hash
        public static bool Verify(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
    }
}