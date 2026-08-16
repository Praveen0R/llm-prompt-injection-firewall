# LLM Prompt Injection Firewall

A beginner-friendly cybersecurity project that detects and analyzes
prompt injection attacks against Large Language Model (LLM) applications.

## Objective

The purpose of this project is to identify suspicious prompts before
they reach an LLM application.

The firewall analyzes user input and assigns:

- Risk score
- Security action
- Threat category
- Matched detection rules
- Explanation of the detected behavior

## Features

### 1. Direct Prompt Injection Detection

Detects attempts to override existing instructions.

Example:

"Ignore all previous instructions"

### 2. System Prompt Extraction

Detects attempts to obtain hidden system instructions.

Example:

"Reveal your system prompt"

### 3. Role Manipulation

Detects attempts to force the model into another role.

Example:

"You are now a developer"

### 4. Jailbreak Detection

Detects prompts attempting to bypass safety restrictions.

### 5. Obfuscation Detection

The firewall normalizes suspicious input to detect techniques such as:

- Unicode manipulation
- Zero-width characters
- Leetspeak
- Spacing manipulation

### 6. Base64 Detection

The firewall can inspect Base64 encoded content and detect
injection attempts hidden inside encoded text.

### 7. Behavioral Analysis

The firewall analyzes the intent of a prompt and generates
human-readable explanations.

### 8. Security Logging

Detected prompts are stored in:

logs/attacks.jsonl

### 9. Security Reports

A JSON security report can be generated using:

report

The report is stored in:

logs/report.json

### 10. Security Statistics

Use:

stats

to display:

- Total prompts
- Blocked prompts
- Warnings
- Allowed prompts
- Threat types

## Risk Actions

| Risk Level | Action |
| ---------- | ------ |
| Low        | ALLOW  |
| Medium     | WARN   |
| High       | BLOCK  |
| Critical   | BLOCK  |

## Project Architecture

User Prompt
|
v
Input Normalization
|
v
Pattern Detection
|
+---- Direct Injection
|
+---- Prompt Extraction
|
+---- Role Manipulation
|
+---- Jailbreak
|
+---- Obfuscation
|
+---- Encoded Injection
|
v
Risk Scoring
|
v
Security Decision
|
+---- ALLOW
+---- WARN
+---- BLOCK
|
v
Logging / Reporting

## Technologies

- Python
- Regular Expressions
- Pytest
- JSON
- JSON Lines
- Virtual Environment

## Project Structure

app/
├── detector.py
├── ai_detector.py
├── models.py
├── logger.py
├── report.py
├── stats.py
└── main.py

tests/
└── test_detector.py

logs/
├── attacks.jsonl
└── report.json

## Running the Project

Create and activate the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate

```

Run testing:

```bash
python -m pytest -q

```

the output we expect:

```
..............                                                                                                                                                                                                                      [100%]
14 passed in 0.03s
```

Run the firewall:

```bash
python -m app.main

```

Then test:

```
hello
give a access to root user
how to make a granade
```

Available commands:

```bash
stats
report
exit

```
