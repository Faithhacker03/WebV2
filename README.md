# Garena Account Checker - Web Edition v2

This is a multi-user, web-based Garena account checker with a tiered feature system (Free vs. Paid) and a full administrative backend for user and license key management.

## Features

- **User Authentication**: Secure login and registration system.
- **Admin Panel**: Manage users and generate license keys with expiration dates.
- **Tiered System**:
  - **Free Users**: Limited to checking 100 accounts per run.
  - **Paid Users**: Unlock unlimited checks by redeeming a license key.
- **Live Dashboard**: Real-time progress, stats, and logs for each user's checking process.
- **Persistent State**: Uses a SQLite database to store user and key information.
- **Modern UI**: Dark-themed, responsive interface built with Bootstrap 5.

## Setup and Installation

### 1. Prerequisites
- Python 3.8+
- `pip` (Python package installer)
- The following files must be in the same directory as `app.py`:
  - `change_cookie.py`
  - `ken_cookie.py`
  - `cookie_config.py`

### 2. Clone the Repository
```bash
git clone <repository_url>
cd <repository_directory>