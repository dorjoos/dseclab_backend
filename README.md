# D-sec Lab Threat Intelligence Platform

A comprehensive Threat Intelligence management system designed for enterprise customers including banks, telecommunications operators, government agencies, and other critical infrastructure organizations. Built with Flask, SQLAlchemy, Flask-Admin, and Flask-Login.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

### 1. Clone or Navigate to the Project

```bash
cd /Users/jooy/Development/dseclab_backend
```

### 2. Create a Virtual Environment

It's recommended to use a virtual environment to isolate project dependencies:

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

**On macOS/Linux:**
```bash
source venv/bin/activate
```

**On Windows:**
```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

This will install the following packages:
- Flask (>=2.0.0)
- Flask-SQLAlchemy (>=3.0.0)
- Flask-Login (>=0.6.0)
- Flask-Admin (>=1.6.0)
- Flask-Assets (>=2.0)
- libsass (>=0.21.0)

### 5. Initialize the Database

The application uses SQLite database. The database file will be created automatically in the `instance/` directory when you first run the application.

If you need to create the database tables manually:

```bash
cd staterkit
python -c "from cuba import app, db; app.app_context().push(); db.create_all()"
```

## Running the Application

### Start the Development Server

```bash
cd staterkit
python run.py
```

Or from the project root:

```bash
cd staterkit
source ../venv/bin/activate  # if not already activated
python run.py
```

The application will start on `http://localhost:8003` (as configured in `run.py`).

### Access the Application

Open your browser and navigate to:
- Main application: `http://localhost:8003`
- Admin interface: `http://localhost:8003/admin` (requires admin authentication)

## Authentication

- Login: `http://localhost:8003/login`
- Registration: `http://localhost:8003/register`
- Logout: `http://localhost:8003/logout`

Passwords are stored as secure hashes (Werkzeug). Sessions are managed by Flask-Login.

### Create an initial admin user

Activate the virtual environment and run:

```bash
cd staterkit
python -c "from cuba import app, db; from cuba.models import User; app.app_context().push(); user = User(username='admin', email='admin@example.com', isAdmin=True); user.set_password('change_me'); db.session.add(user); db.session.commit(); print('Admin created: admin@example.com / change_me')"
```

Update the password (`change_me`) before using in production.

## Project Structure

```
dseclab_backend/
├── staterkit/              # Main application directory
│   ├── cuba/               # Application package
│   │   ├── __init__.py     # Flask app initialization
│   │   ├── models.py       # Database models
│   │   ├── routes.py       # Application routes
│   │   ├── static/         # Static files (CSS, JS, images)
│   │   └── templates/       # Jinja2 templates
│   ├── instance/           # Instance-specific files
│   │   └── cuba.db         # SQLite database (created automatically)
│   └── run.py              # Application entry point
├── requirements.txt        # Python dependencies
└── venv/                  # Virtual environment (created during setup)
```

## Configuration

The application configuration is set in `staterkit/cuba/__init__.py`:

- **SECRET_KEY**: Used for session management (change in production!)
- **SQLALCHEMY_DATABASE_URI**: SQLite database path
- **Port**: 8003 (configured in `run.py`)

## Features

- **Flask-Admin**: Admin interface for managing database models
- **Flask-Login**: User authentication and session management
- **SQLAlchemy**: ORM for database operations
- **Flask-Assets**: Asset management and compilation
- **SCSS Support**: Pre-compiled CSS files (SCSS source available)

## Troubleshooting

### Import Errors

If you encounter import errors, make sure:
1. The virtual environment is activated
2. All dependencies are installed: `pip install -r requirements.txt`
3. You're running from the correct directory

### Database Issues

If the database doesn't exist:
- The database will be created automatically on first run
- Or manually create it using the initialization command above

### Port Already in Use

If port 8003 is already in use, you can change it in `staterkit/run.py`:
```python
app.run(debug=True, port=8004)  # Change to any available port
```

### SassMiddleware Warning

The application includes optional SCSS compilation support. If you see warnings about `sassutils`, they can be safely ignored as the CSS files are already pre-compiled and available.

## Development

### Running in Debug Mode

The application runs in debug mode by default (as configured in `run.py`). This enables:
- Automatic reloading on code changes
- Detailed error messages
- Debug toolbar (if configured)

**Note**: Never run in debug mode in production!

## Production Deployment

For production deployment:

1. Set `debug=False` in `run.py`
2. Change the `SECRET_KEY` to a secure random value
3. Use a production WSGI server (e.g., Gunicorn, uWSGI)
4. Configure proper database (PostgreSQL, MySQL, etc.)
5. Set up proper logging and error handling

## License

[Add your license information here]

