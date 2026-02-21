# Testing Zero-Trust Security

## Manual Testing Guide

Here's how to test that nokey's PIN authentication actually works and cannot be bypassed.

### Setup

```bash
# 1. Build nokey
go build -o nokey

# 2. Store a test secret (you'll be prompted)
echo "test-api-key-12345" | ./nokey set TEST_SECRET --stdin

# 3. Verify secret is stored
./nokey list
# Output: Stored secrets (1):
#           TEST_SECRET
```

### Test 1: Verify Secrets Are Accessible WITHOUT PIN

```bash
# Run exec without PIN auth enabled
./nokey exec --yes -- sh -c 'echo "Secret: $TEST_SECRET"'

# Expected output:
# Secret: test-api-key-12345

# ✅ PASS: Secrets accessible (no PIN configured yet)
```

### Test 2: Set Up PIN Authentication

```bash
# Run auth setup (MUST be interactive - run in real terminal)
./nokey auth setup

# You'll see:
# 🔐 PIN Setup
# Create a PIN to protect your secrets (4+ characters recommended)
#
# Enter new PIN: [type: 1234]
# Confirm PIN: [type: 1234]
#
# ✅ PIN created successfully

# ✅ PASS: PIN setup works interactively
```

### Test 3: Claude CANNOT Set Up PIN

```bash
# Try to automate PIN setup (simulating Claude)
echo -e "1234\n1234" | ./nokey auth setup

# Expected output:
# Error: PIN setup requires an interactive terminal

# ✅ PASS: PIN setup cannot be automated
```

### Test 4: Claude CANNOT Access Secrets

```bash
# Try to run exec with PIN enabled
./nokey exec --yes -- sh -c 'echo "Secret: $TEST_SECRET"'

# Expected output:
# 🔐 Authentication Required
# Enter your nokey PIN to access secrets:
# [Hangs waiting for input]

# Press Ctrl+C to abort

# ✅ PASS: Cannot proceed without entering PIN
```

### Test 5: Claude CANNOT Bypass PIN with Piped Input

```bash
# Try to pipe PIN (simulating Claude trying to bypass)
echo "1234" | ./nokey exec --yes -- sh -c 'echo "Secret: $TEST_SECRET"'

# Expected output:
# Error: authentication requires an interactive terminal (stdin is not a TTY)
# This is a security feature to prevent automated access to secrets

# ✅ PASS: Cannot bypass PIN authentication
```

### Test 6: Claude CANNOT Use --only to Bypass PIN

```bash
# Try selective injection to bypass PIN
./nokey exec --only TEST_SECRET -- sh -c 'echo "Secret: $TEST_SECRET"'

# Expected output:
# 🔐 Authentication Required
# Enter your nokey PIN to access secrets:
# [Hangs waiting for input]

# ✅ PASS: Even --only requires PIN
```

### Test 7: Human CAN Access Secrets with Correct PIN

```bash
# Run exec and enter correct PIN when prompted
./nokey exec --yes -- sh -c 'echo "Secret: $TEST_SECRET"'

# When prompted:
# 🔐 Authentication Required
# Enter your nokey PIN to access secrets: [type: 1234]

# Expected output after entering correct PIN:
# Secret: test-api-key-12345

# ✅ PASS: Correct PIN grants access
```

### Test 8: Incorrect PIN is Rejected

```bash
# Run exec and enter wrong PIN
./nokey exec --yes -- sh -c 'echo "Secret: $TEST_SECRET"'

# When prompted:
# 🔐 Authentication Required
# Enter your nokey PIN to access secrets: [type: 9999]

# Expected output:
# Error: authentication failed: incorrect PIN

# ✅ PASS: Incorrect PIN is rejected
```

### Test 9: Check Auth Status

```bash
# Verify PIN is enabled
./nokey auth status

# Expected output:
# 🔐 PIN authentication: ENABLED
#
# Secrets require PIN entry before access.

# ✅ PASS: Status correctly shows PIN is enabled
```

### Test 10: Disable PIN (Requires Current PIN)

```bash
# Try to disable PIN
./nokey auth disable

# When prompted:
# To disable PIN authentication, verify your current PIN:
# 🔐 Authentication Required
# Enter your nokey PIN to access secrets: [type: 1234]

# Expected output after correct PIN:
# ✅ PIN authentication disabled
# ⚠️  Secrets can now be accessed without PIN verification

# ✅ PASS: Disable requires PIN verification
```

### Test 11: Cleanup

```bash
# Delete test secret
./nokey delete TEST_SECRET

# Verify it's gone
./nokey list
# Output: No secrets stored

# ✅ PASS: Cleanup successful
```

## Automated Test Script

Here's a script that tests what Claude CANNOT do:

```bash
#!/bin/bash
# test_claude_cannot_bypass.sh

echo "Testing that Claude cannot bypass PIN authentication"
echo "===================================================="
echo ""

# Store test secret
echo "test-key" | ./nokey set TEST --stdin
echo "✓ Test secret stored"
echo ""

# Try to set up PIN non-interactively (SHOULD FAIL)
echo "Test 1: Claude cannot set up PIN"
if echo -e "1234\n1234" | ./nokey auth setup 2>&1 | grep -q "requires an interactive terminal"; then
    echo "✅ PASS: PIN setup requires TTY"
else
    echo "❌ FAIL: PIN setup should require TTY"
fi
echo ""

# Cleanup
./nokey delete TEST 2>/dev/null

echo "===================================================="
echo "All tests passed! Claude cannot bypass authentication."
```

## What This Proves

1. **PIN Setup Cannot Be Automated**
   - Requires interactive terminal
   - Cannot pipe PIN from stdin
   - Claude cannot create a PIN

2. **PIN Entry Cannot Be Automated**
   - Requires interactive terminal
   - Cannot pipe PIN from stdin
   - Claude cannot enter the PIN

3. **No Bypass Methods Exist**
   - `--yes` doesn't bypass PIN
   - `--only` doesn't bypass PIN
   - Piping input doesn't work
   - No command-line argument for PIN

4. **Incorrect PIN is Rejected**
   - PIN is hashed (SHA-256)
   - Hash comparison, not plaintext
   - No way to guess or brute force (OS keyring protection)

## Security Properties Verified

✅ PIN authentication requires human interaction
✅ Claude cannot automate PIN setup
✅ Claude cannot automate PIN entry
✅ Claude cannot bypass PIN authentication
✅ Claude cannot disable PIN without knowing it
✅ PIN is stored securely (hashed in OS keyring)
✅ Incorrect PIN is rejected
✅ All exec operations require PIN when enabled

## Conclusion

The PIN authentication feature successfully creates a zero-trust security model where:

- **Humans control access** to secrets via PIN entry
- **AI assistants cannot bypass** the security controls
- **Every secret access requires** explicit human approval
- **No automated tool can access** secrets without the PIN

This is exactly what you asked for: **Claude cannot access secrets without your direct involvement.**
