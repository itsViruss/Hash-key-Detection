# Hash Key Detection Simulator

Hash Key Detection Simulator is a full-stack Flask application that teaches students how file hashing, integrity verification, man-in-the-middle tampering, MD5 collisions, and digital signatures work together.

## Features

- Upload any file and store it temporarily on the server.
- Generate `MD5`, `SHA-1`, or `SHA-256` using Python `hashlib`.
- Browse four navigation tabs: `Hash Tool`, `Secure Transfer`, `Simulation Lab`, and `Activity Logs`.
- Use the Hash Tool page to generate a hash, inspect file size, and copy the result.
- Use the Secure Transfer page for sender-to-receiver verification, delivery simulation, digital signatures, AES-style encryption simulation, and logged transfer activity.
- Use the Simulation Lab terminal to issue safe simulated commands such as `load file`, `show hex`, `append`, `send`, and `verify` without writing logs.
- Demonstrate an MD5 collision with two predefined files that share the same MD5 hash.
- Simulate digital signatures with an RSA key pair using `cryptography`.
- Store a JSON activity log with timestamp, hash, filename, and result for Secure Transfer actions only.

## Project Structure

```text
hash-simulator/
|-- app.py
|-- Dockerfile
|-- README.md
|-- requirements.txt
|-- data/
|   `-- logs.json
|-- demo_collisions/
|   |-- md5_collision_a.txt
|   `-- md5_collision_b.txt
|-- static/
|   |-- css/
|   |   `-- style.css
|   `-- js/
|       `-- app.js
|-- templates/
|   `-- index.html
`-- uploads/
```

## Routes

- `/` - Redirects to the Hash Tool
- `/hash` - Hash Tool page
- `/transfer` - Secure Transfer page with log generation
- `/simulation` - Simulation Lab with a simulated hacker terminal and no log writes
- `/logs` - Activity log table for Secure Transfer runs

## Run Without Docker

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the Flask app:

```bash
python app.py
```

4. Open `http://localhost:5000`.

## Run With Docker

```bash
docker build -t hash-simulator .
docker run -p 5000:5000 hash-simulator
```

Then open `http://localhost:5000`.

## How the Simulator Works

1. In Hash Tool, the user uploads a file and generates an integrity hash instantly.
2. In Secure Transfer, the sender uploads a file, optionally enables digital signature and AES-style encryption simulation, and sends it to a simulated recipient.
3. The server computes the original hash and verifies the receiver-side result after delivery.
4. In Simulation Lab, the attacker modifies the file only through safe simulated terminal commands.
5. The UI reports whether the file stayed safe or was tampered with, and only Secure Transfer actions are logged.

## Notes

- Uploaded files are stored in the `uploads/` directory for demonstration purposes.
- The JSON log is saved in `data/logs.json`.
- The digital signature flow uses the library's signing and verification primitives, which represent the educational idea of hashing first and validating with the public key.
