#CatalogApp
An application provides a list of items within a variety of categories as well as a user
registration and authentication system. Registered users have the ability to post, edit
and delete their own items.

#Requirements
To run application you have to create Python virtual environment and install all packages
from the requirements.txt:
    1. Create virtual environment: python3 -m venv Catalog_app_venv
    2. Activate virtual environment: source catalog_app_venv/bin/activate
    3. Install all dependencies: pip install -r requirements.txt

LogAnalysis application connects to the database named "catalog". Before any use of the application the database server
must exist, server must have the database named "catalog", and database must contain the data

You may run 'addcategories.py' file to create all tables and seed initial data.

#Application usage
After you have installed all dependencies, you may run application.

In order to run your application you have to activate virtual environment (if it is not activated yet), and execute this command:

python application.py


