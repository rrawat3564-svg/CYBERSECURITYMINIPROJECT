# Cybersecurity Mini Project - Phishing URL Checker

## Project Overview
This project is a simple Python tool to detect phishing URLs using heuristic analysis. It helps users identify suspicious links before clicking.

## Objective
To protect users from phishing attacks by analyzing URL patterns commonly used by attackers.

## Features Checked
1.  IP address instead of domain name
2.  Use of @ symbol for redirection
3.  Unusually long URL
4.  Too many subdomains (dots)
5.  Suspicious keywords like login, verify, account
6.  Missing HTTPS
7.  Hyphen in domain name

## How it Works
The program gives a Risk Score out of 7. If score >= 3, URL is marked as Suspicious.

## How to Run
```bash
python phishing_checker.py
