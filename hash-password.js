const bcrypt = require('bcrypt');

// This script generates a bcrypt hash for a given password.
// Usage: node hash-password.js <your_password_here>

const myArgs = process.argv.slice(2);
const password = myArgs[0];

if (!password) {
    console.error('💀 Please provide a password to hash.');
    console.log('Usage: node hash-password.js <your_password_here>');
    process.exit(1);
}

const saltRounds = 10;

bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) {
        console.error('Error hashing password:', err);
        return;
    }
    console.log('Your hashed password is:');
    console.log(hash);
});
