const {
    MY_SQL_HOST,
    MY_SQL_PORT,
    MY_SQL_USER,
    MY_SQL_PASS,
    MY_SQL_DATABASE,
    DB_CLIENT
} = process.env;


const knex = require('knex').knex({
    client: DB_CLIENT,
    connection: {
        host: MY_SQL_HOST,
        port: MY_SQL_PORT,
        user: MY_SQL_USER,
        password: MY_SQL_PASS,
        database: MY_SQL_DATABASE
    }
});


module.exports = knex;
