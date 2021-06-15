# OR2STEM API

API for the OR2STEM project.

# Configuration

Environment variables are used for configuration settings. For local
development rename the `env-example.txt` to `.env` and update the values
appropriately.

# Running Locally


## Configuration

Requires a `.env` file in the root of the project directory.

## Database Setup

Sqlite is used for local development. See the section
`Database > Initializing` below for information on how to seed the
database.

## Running with Python

Requires Python 3.8 or higher.

### Virtualenv Setup

It is recommended to set up a virtualenv for the project

    python -m venv .venv

on Windows activate the environment

    .venv\scripts\activate

or if on Linux

    .venv/bin/activate

then install the project dependencies

    pip install -r requirements.txt

### Running

To run the project

    python -m scale_api.app

This will start up the server using self-signed certificates on port 443 and
can be accessed via

    https://localhost/api

## Running with Docker

Docker is the recommended method to run a local server. For an alternative,
the server can be run using Python (see following section).

The recommended method is to use the provided `docker-compose.yml`:

    docker-compose up --build

This will start the container and make the api available on port `443`

    https://localhost/api

# API Documentation

OpenAPI schema documentation is available at:

    https://localhost/api/docs

# Database

## Database Setup

The commands below require the use of `psql`, to run from docker use:

    docker-compose up -d scale_db
    docker-compose exec scale_db psql -U scale_api -h stem-scale-db.priv.fresnostate.edu swa

The following commands must be run on a new Postgres server in order to create
the database, user and associated schema where the database objects will be
store for the application.

```sql
create database swa;

\c swa

create user scale_api with password '<insert password here>';

-- For the following `create schema` command to work in RDS when connected as
-- the superuser, you will have to grant the new role (user) to them, for
-- example:
--
--     GRANT scale_api TO postgres;
--
create schema if not exists authorization scale_api;

grant select on all tables in schema public to scale_api;
```

## Initializing

The database tables can be initialized from a json file. For an example, see
`scale_initdb-example.json`. Make a copy of this file and pass it as an
argument to the initdb script (see below).

Before running the initdb script, ensure you have a properly configured `.env`
file and execute:

    python scale_initdb.py [path to json seed file]

If an argument is not provided, it assumes there is a file in the same directory
named `scale_initdb.json` and will use it to initialize the database.

## Migrations

Ensure you have a properly configured `.env`.

Alembic is configured to use the SQLAlchemy metadata so that automated
migrations can be generated with the following command:

    alembic revision --autogenerate -m "<commit message>"

The resulting migration file should be reviewed to ensure it captured all
the required changes correctly.

To update the database to the current revision run:

    alembic upgrade head
