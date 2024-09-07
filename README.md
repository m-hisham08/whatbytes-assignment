# WhatBytes Assignment

This project is a Django-based web application with user authentication features.

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Installation

1. Clone the repository:

   ```
   git clone https://github.com/m-hisham08/whatbytes-assignment.git
   cd whatbytes-assignment
   ```

2. Create a virtual environment:

   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - Copy `sample_env_file.txt` to `.env`
   - Update the `.env` file with your email configuration:
     ```
     EMAIL_HOST=smtp.gmail.com
     EMAIL_HOST_USER=<Your Email Here>
     EMAIL_HOST_PASSWORD=<Your App Password>
     EMAIL_USE_TLS=True
     EMAIL_PORT=587
     ```

### Running the Project

1. Apply migrations:

   ```
   python3 manage.py migrate
   ```

2. Load environment variables:

   ```
   source .env
   ```

3. Run the development server:
   ```
   python3 manage.py runserver
   ```

## Features

- User registration and login
- Email verification
- Password reset functionality
- User dashboard and profile pages

## Project Structure

```
.
├── authentication/      # User authentication app
├── static/              # Static files (CSS, JS)
├── templates/           # HTML templates
├── whatbytes_assignment/# Main project directory
├── manage.py            # Django management script
├── requirements.txt     # Project dependencies
├── sample_env_file.txt  # Sample environment variables
└── vercel.json          # Vercel deployment configuration
```

## Deployment

This project is configured for deployment on Vercel. The `vercel.json` file and `build_files.sh` script are included for this purpose.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).
