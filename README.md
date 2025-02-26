# Secure-Password-Generator-with-Entropy-Analysis

**Secure Password Generator with Entropy Analysis** is a Python-based tool designed to generate strong, random passwords, enforce password policies, calculate entropy, and apply cryptographic salting for enhanced security. This tool provides users with a way to create secure passwords while ensuring compliance with recommended security standards.

## Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Example Execution](#example-execution)
- [Output](#output)
- [Purpose](#purpose)
- [License](#license)

## Features
- **Random Password Generation**: Creates secure passwords with a mix of uppercase, lowercase, digits, and special characters.
- **Password Policy Enforcement**: Ensures passwords meet security criteria such as minimum length, character diversity, and complexity.
- **Entropy Calculation**: Provides an estimate of password strength in bits to assess security levels.
- **Salting & Hashing**: Uses bcrypt to add cryptographic salt and hash passwords securely.
- **Educational Security Tips**: Offers best practices for password management and security awareness.

## Tech Stack
This project is built using the following technologies:

- **Python**: The core programming language used to develop the tool.
- **bcrypt**: Library for cryptographic hashing and salting of passwords.
- **random & string**: Used for secure random password generation.
- **re**: Regular expressions for enforcing password policies.
- **math**: Utilized for entropy calculations to measure password strength.

## Getting Started

### Prerequisites
To run this tool, ensure the following prerequisites are met:

- **Python 3.x** installed on your system.
- **pip** (Python package manager) for installing dependencies.

### Installation

Follow these steps to set up the project:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/11x-singhamit/Secure-Password-Generator-with-Entropy-Analysis.git
   ```

2. **Navigate into the project directory**:
   ```bash
   cd Secure-Password-Generator-with-Entropy-Analysis
   ```

3. **Install dependencies**:
   ```bash
   pip install bcrypt
   ```

The program is now ready to use.

## Usage

Run the password generator script using the following command:

```bash
python password_generator.py
```

### Example Execution:
```
Enter the desired length of the password (12-20 characters recommended): 16

Generated Password:
A#v7@pL9!mXr2Qd$

Password Policy:
- Minimum length of 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

Password meets policy requirements.

Salted and Hashed Password:
$2b$12$3TsdwUVU9YrXt1JHGCM3gu7P5j... (hashed output)

Password Entropy:
98.47 bits

Educational Tips:
- Use a password manager to store unique passwords.
- Enable two-factor authentication wherever possible.
- Never reuse passwords across different services.
```

## Output
The tool provides the following outputs:
- **Generated Password**: A randomly generated password meeting security policies.
- **Password Policy Validation**: Ensures compliance with best practices.
- **Salted & Hashed Password**: Securely hashed output using bcrypt.
- **Entropy Calculation**: Measures password strength in bits.
- **Security Recommendations**: Educational tips for password security.

## Purpose
The primary objective of this project is to create a robust password generation and evaluation tool that aids users in enhancing their password security. This tool is useful for:
- Individuals needing strong passwords for accounts.
- Security professionals assessing password strength.
- Educational purposes to understand entropy and hashing.

## License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more information.

---
Feel free to contribute, report issues, or suggest improvements by opening a GitHub issue or submitting a pull request.

