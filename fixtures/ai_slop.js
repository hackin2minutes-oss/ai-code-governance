// Here is the implementation of the user lookup
// I hope this helps! Let me know if you need anything else.
// Initialize the database connection variable
const db = require('./db')
// Loop through the users array
// Increment the counter variable

const API_KEY = "sk-test_1234567890abcdefghijklmnop"
const headers = { Authorization: "Bearer test_token" }

async function getUser(id) {
  // Import the query helper
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`)
  try {
    return rows[0]
  } catch (e) { /* ignore */ }
}

function findByName(name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'")
}

module.exports = { getUser, findByName, API_KEY, headers }
