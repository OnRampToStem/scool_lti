# Student Centered Open Online Learning (SCOOL)

The main use of this project is to provide integration to Learning Management
Systems (LMS) using Learning Tools Interoperability (LTI) v1.3. This includes
handling course module launch requests in order to determine the user's role
(Instructor or Learner), retrieving all users in the course and posting scores
to the grade book.

## Configuration

Environment variables are used for configuration settings. For local
development review the `scool.settings` module and create a `.env` file
in the project root with the settings that are needed.

## Running with Python

Requires Python 3.13.

### Virtualenv Setup

It is recommended to set up a virtualenv for the project

```shell
python -m venv .venv
```

on Windows activate the environment

```shell
.venv\scripts\activate
```

or if on Linux

```shell
.venv/bin/activate
```

then install the project dependencies

```shell
pip install -r requirements-dev.txt
```

## Running

To run the project

```shell
python -m scool
```

This will start up the server using self-signed certificates on port 443 and
can be accessed via

<https://localhost/api>

## Running with Docker

Docker is the recommended method to run a local server. For an alternative,
the server can be run using Python (see following section). When running with
`docker-compose`, an Apache proxy and Postgres database will be used to
closely reflect the production environment.

The recommended method is to use the provided `docker-compose.yml`:

```shell
docker-compose up --build
```

This will start the container and make the api available on port `443`

<https://localhost/api>

## API Documentation

OpenAPI schema documentation is available at:

<https://localhost/api/docs>

## Database

### Database Setup

The commands below require the use of `psql`, to run from docker use:

```shell
docker-compose up -d db
docker-compose exec db psql -U postgres -h scool-db.host.edu swa
```

The following commands must be run on a new Postgres server in order to create
the database, user and associated schema where the database objects will be
store for the application.

```sql
create database swa;

\c swa

create user scool with password '<insert password here>';

-- For the following `create schema` command to work in RDS when connected as
-- the superuser, you will have to grant the new role (user) to them, for
-- example:
--
--     GRANT scool TO postgres;
--
create schema if not exists authorization scool;

grant select on all tables in schema public to scool;
```

### Migrations

Ensure you have a properly configured `.env`.

Alembic is configured to use the SQLAlchemy metadata so that automated
migrations can be generated with the following command:

```shell
alembic revision --autogenerate -m "<commit message>"
```

The resulting migration file should be reviewed to ensure it captured all
the required changes correctly.

To update the database to the current revision run:

```shell
alembic upgrade head
```
