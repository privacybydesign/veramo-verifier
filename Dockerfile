FROM node:22-alpine
WORKDIR /app

COPY package.json yarn.lock .yarnrc.yml ./

RUN yarn install

COPY . .

RUN apk add --no-cache postgresql-client

CMD ["sh", "-c", "PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p ${DB_PORT:-5432} -U $DB_USER -d $DB_NAME -c 'CREATE SCHEMA IF NOT EXISTS verifier' && exec yarn start"]
