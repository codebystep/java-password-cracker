# Password Cracker and Diffie-Hellman Key Analyzer (A21B0625P)

This Java project implements two main functionalities for cryptographic analysis:

---

## 🔐 Task 4a: Password Cracking (Runtime ≈ 3 minutes)

The program attempts to crack hashed passwords using a combination of dictionary attacks and brute-force methods.

### Process:
1. Loads a list of user passwords and their hashes from `password_database.csv`.
2. Identifies users by personal ID.
3. Loads a dictionary of possible passwords from `10000hesel.txt`.
4. For each hashed password:
   - Tries to find a match in the dictionary.
   - If not found, uses brute-force within a defined time limit (`maxDelkaVeVterinach` = 180s).
5. For each password, a result object is created with:
   - Cracked password (if found)
   - Number of attempts
   - Execution time
   - Original password hash

### Output:
Cracked password results are stored in `cracked_results_A21B0625P.csv`.

---

## 🔓 Task 4b: Diffie-Hellman Key Cracking (Runtime ≈ 5 minutes)

This functionality attempts to derive private keys based on public Diffie-Hellman parameters.

### Process:
1. Loads public keys from `diffie_hellman_keys.csv`.
2. For each entry:
   - Applies the `crackPrivateKey()` method using:
     - Prime number `p`
     - Generator `g`
     - Public key `gxModP`
     - Length of the private key
3. If the cracking process exceeds `MAX_RUNTIME` (15 minutes), the program terminates.

### Output:
Recovered private keys are stored in `alices_private_keys_A21B0625P.csv`.

---

## 📦 Utility Methods

- `readCsvFile()` – Loads data from a CSV file as a `List<String[]>`.
- `writeCsvFile()` – Saves data into a CSV file.

---

**Note:** This project is for educational purposes only.
