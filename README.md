# Simple Web App



## How To Use
Before starting it up make sure that all the credentials are provided in `.env` file.

You can run application as is but it is recommended to change passwords, database names and etc. for using in production env.

`DJANGO_DB_NAME` -- is used for database name.

`DJANGO_DB_USER` -- is used for user oh whose behalf will be services interacting with DB.

`DJANGO_DB_PASSWORD` -- is used for password got `DJANGO_DB_USER`.

`DJANGO_DB_PORT` -- is used for specification which port will be used for accessing DB. Do not change this value because it won't work on this version.

`DJANGO_ADMIN_USER` -- is username for creating Django user for site you will get access on `http://localhost:8081/`

`DJANGO_ADMIN_MAIL` -- is email for Django user

`DJANGO_ADMIN_PASSWORD` -- is password for Django user

`POSTGRES_USER` -- is used for database service account

`POSTGRES_PASSWORD` -- is used for database service account


After setting all needed variables you can finally lauch the program.

```
docker-compose build
docker-compose up -d
```

After a few seconds you can access the server at `http://localhost:8081/login`.


## Services Description
`web` -- Django service which provides web site for interaction with users who have written to the bot.

`db` -- PostgreSQL database which is used to store data about users who write to bot and for Django database also.


## Checking Health

`http://localhost:8081/health` -- get health of services.

## Development

If you eager to develop some new features, it is useful to stick to some rules:
1. Use [pre-commit](https://pre-commit.com) hooks defined in `pre-commit-config.yaml`. Install it in your .git dir or run manually before every commit.
2. Project contains env.sh file that is handy to set env variables so that it is easy to run web server via `python manage.py runserver`
