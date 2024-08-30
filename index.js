const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const bodyParser = require('body-parser');
const express = require('express');
const knex = require('./knexfile');
const app = express();

app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('mi secreto'));
app.use(session({
    secret: '-------',
    resave: false,
    saveUninitialized: false
    }));
    
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const result = await knex.select('username', 'email').from('users').where({ id: id })
        done(null, result);
    } catch (error) {
        done(error, null);
    }
});


//Crear Usuarios
app.post('/users', async (req, res) => {
    try {
        console.log(req.body);
        const { username, email, password, nationality_id } = req.body;
        const pwd = await bcrypt.hashSync(password, 10);
        const result = await knex('users').insert({ username, email, password: pwd, nationality_id });
        return res.send(result);
    } catch (error) {
        console.log(error)
        return res.send('ERROR')
    }
});
//Consulta relacionada, obtener usuarios por id de nacionalidad
app.get('/users/nationality/:nationalityId', async (req, res) => {
    try {
        const { nationalityId } = req.params;
       const result = await knex
            .select('username', 'email','nationality_id')
            .from('users')
            .join('nationalities', 'users.nationality_id', 'nationalities.id')
            .where('nationalities.id', nationalityId);
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});

//Obtener Usuarios Paginados localhost:4000/users?limit={numeros de usuarios a obtener}
//Obtener todos los usuarios localhost:4000/users
app.get('/users', async (req, res) => {
    try {
        const { limit } = req.query;
        const result = await knex.select('username', 'email').from('users').limit(parseInt(limit));
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});

//Obtener Usuarios por Id
app.get('/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await knex.select('username', 'email', 'nationality_id').from('users').where({ id: userId });
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});
//Crear Nacionalidades
app.post('/nationalities', async (req, res) => {
    try {
        console.log(req.body);
        const { countryname } = req.body;
        const result = await knex('nationalities').insert({countryname});
        return res.send(result);
    } catch (error) {
        console.log(error)
        return res.send('ERROR')
    }
});
//Obtener Nacionalidades
app.get('/nationalities', async (req, res) => {
    try {
        const { limit } = req.query;
        const result = await knex.select('countryname').from('nationalities');
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});

passport.use(new LocalStrategy({
    usernameField: 'username', 
    passwordField: 'password' 
}, (username, password, done) => {
    knex('users')
    .where({ username: username })
    .first()
    .then(user => {
        if (!user) {
            return done(null, false, { message: 'Nombre de usuario o contraseña incorrectos' });
        }
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return done(err);
            }
            if (isMatch) {
                return done(null, user);
            } else {
                console.log({ message: 'Nombre de usuario o contraseña incorrectos' });
                return done(null, false, { message: 'Nombre de usuario o contraseña incorrectos' });
            }
        });
    })
    .catch(err => {
        return done(err);
    });
}));

app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login-fail',
}));   

app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.send(`<h1>Bienvenido!</h1>`);
    } else {
        res.redirect('/login-fail');
    }
});

app.get('/login-fail', (req, res) => {
    res.status(400).send('Usuario o contraseña invalida!')
});

app.listen(4000, () => {
    console.log('Listening on port 4000');
   
});


