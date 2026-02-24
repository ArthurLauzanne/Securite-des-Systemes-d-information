# Project Report 1: Fundamentals and Identification/Authentication
**Author:** [Lauzanne_Arthur Ligneres_Romain]

# Part 1A: Environment Setup (Kali Linux VM)
[cite_start]The objective was to set up a secure laboratory environment[cite: 23, 24]. [cite_start]I chose the VirtualBox option for maximum isolation[cite: 26].

* [cite_start]**OS:** Kali Linux 64-Bit[cite: 42].
* [cite_start]**System Settings:** 4GB RAM and 30GB Disk[cite: 48, 53].
* [cite_start]**Network:** Configured as "Internal Network" to isolate the lab from the internet[cite: 58, 114].

> **[SCREENSHOT_01]**: Replace this with your VirtualBox running Kali.

---

# Part 1B: Password Policy Management (Complexity and Renewal)

## 1. Objective
[cite_start]The goal of this section was to implement a robust password policy on the Kali Linux system to defend against brute-force and dictionary attacks[cite: 123, 133]. [cite_start]We configured strict complexity requirements and a mandatory renewal (aging) policy to ensure credential rotation[cite: 124, 138].

---

## 2. Configuration of Complexity Rules
[cite_start]We used the `pam_pwquality` module to enforce security standards[cite: 141, 143]. We modified the configuration file located at `/etc/security/pwquality.conf`[cite: 151].

**Key Parameters Enforced:**
* [cite_start]**minlen = 12**: Sets the minimum password length to 12 characters[cite: 158].
* [cite_start]**minclass = 4**: Requires at least one character from each of the four classes (uppercase, lowercase, digits, and special characters)[cite: 160].
* [cite_start]**ucredit, lcredit, dcredit, ocredit = -1**: Forces the presence of at least one character of each type[cite: 176, 177, 178, 179].
* [cite_start]**maxrepeat = 3**: Prevents more than 3 consecutive identical characters[cite: 167].
* [cite_start]**gecoscheck = 1**: Ensures the password does not contain personal information from the user's GECOS field[cite: 171].

> **[INSERT image_ca70d5.png here]**
> *Figure 1: Detailed configuration of complexity rules in /etc/security/pwquality.conf.*

---

## 3. System Activation via PAM
[cite_start]To ensure these rules are active during every password change, I verified the configuration in `/etc/pam.d/common-password`[cite: 186, 190]. 

[cite_start]The system was verified to include the following line before the standard Unix module[cite: 197]:
`password requisite pam_pwquality.so retry=3`

> **[INSERT image_ca70d9.png here]**
> *Figure 2: Verification of the PAM stack activation for pwquality.*

---

## 4. Password Expiration Policy (Aging)
[cite_start]To limit the lifespan of potentially compromised credentials, I implemented a 90-day rotation policy[cite: 138, 247].

* [cite_start]**Global Policy**: I updated the `PASS_MAX_DAYS` parameter in `/etc/login.defs` to **90**[cite: 250, 254].
* **User Enforcement**: I applied this limit to the current 'kali' user using the command: `sudo chage -M 90 kali`[cite: 258, 264].

> **[INSERT image_ca7382.png here]**
> *Figure 3: Using the 'chage -l' command to confirm the 90-day aging limit.*

---

## 5. Security Validation & Testing
[cite_start]I performed manual tests to verify the effectiveness of the new policy[cite: 268].

* **Complexity Test**: I attempted to set weak passwords (too short, or missing character classes). [cite_start]The system successfully rejected these attempts[cite: 272, 274].
* **Expiration Test**: I used `sudo chage -d 0 kali` to force immediate expiration[cite: 281, 282]. Upon the next login attempt, the system prompted for a mandatory password change[cite: 284].

> **[INSERT image_ca7387.png here]**
> *Figure 4: Terminal logs showing system rejection of weak passwords and successful update of a complex password.*

> **[INSERT image_ca73c0.png here]**
> *Figure 5: Forced password change prompt at login after setting age to 0.*

---

## 6. Troubleshooting
During the setup, I encountered a **DNS resolution error** (`Temporary failure resolving 'http.kali.org'`) while trying to install the `libpam-pwquality` package.
* [cite_start]**Issue**: The VM was initially in "Internal Network" mode, which isolates it from the internet[cite: 114].
* **Resolution**: I temporarily switched the VirtualBox network adapter to **NAT mode** to allow internet access for package installation, then successfully proceeded with the configuration.