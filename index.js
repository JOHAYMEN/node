const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { generateThermalPdf } = require('./Utils');
const { jsPDF } = require('jspdf');
require('jspdf-autotable');
const moment = require('moment');
const nodemailer = require('nodemailer');
const validator = require('validator');

const multer = require('multer');
const path = require('path');
const fs = require('fs');

const bodyParser = require('body-parser');
const express = require('express');
const http = require('http'); // Importar http para usar con WebSockets
const WebSocket = require('ws');
const knex = require('./knexfile');
const app = express();
const cors = require('cors');
const flash = require('connect-flash');

app.use(cors({
    origin: 'http://localhost:5173', // La URL de tu frontend
    methods: ['GET', 'POST', 'PATCH', 'PUT'],
    credentials: true
}));
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('mi secreto'));
app.use(session({
    secret: '-------',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
    }));
    
app.use(passport.initialize());
app.use(passport.session());
// Configura connect-flash
app.use(flash());

// Middleware para poner los mensajes flash en res.locals
app.use((req, res, next) => {
    res.locals.messages = req.flash();
    next();
});

passport.use(new LocalStrategy({
    usernameField: 'username', 
    passwordField: 'password' 
}, (username, password, done) => {
    knex('usuarios')
    .where({ username: username })
    .first()
    .then(user => {
        if (!user) {
            return done(null, false, { message: 'Nombre de usuario o contraseña incorrectos' });
        }
        if (user.id < 0) {
            console.log("inhabilitado")
            return done(null, false, { message: 'Usuario inhabilitado' });
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

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const result = await knex('usuarios').select('id','username', 'email').where({ id: id });
        done(null, result);
    } catch (error) {
        done(error, null);
    }
});
app.post('/login', passport.authenticate('local', {
    successRedirect: '/user-info',
    //failureRedirect: '/',
    failureFlash: true
}));   



app.get('/login-fail', (req, res) => {
    res.status(400).send('Usuario o contraseña invalida!')
});
//Ruta para cerrar sesion
// En tu archivo de configuración del servidor 
app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).send('Error al cerrar sesión');
        }
        res.clearCookie('connect.sid'); // Borra la cookie de sesión
        res.status(200).send('Logged out');
    });
});

app.get('/user-info', (req, res) => {
    if (req.isAuthenticated()) {
       // console.log(req.user)
        res.json(req.user);
    } else {
        res.status(401).send('No autenticado');
    }
});


async function generatePdfReport(ventas) {
    const doc = new jsPDF();

    // Títulos de columnas
    doc.autoTable({
        head: [['Fecha', 'Items', 'Total Productos', 'Usuario ID', 'Rol']],
        body: ventas.map(venta => [
            venta.sale_date.toISOString().split('T')[0], // Formato de fecha
            venta.items,
            venta.total_products,
            venta.usuario_id,
            venta.usuario_rol
        ]),
    });

    return doc.output('arraybuffer'); // Devuelve el PDF como un buffer
}

//subir imagenes al server
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        // Verifica si el directorio existe, si no, lo crea
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });
// Endpoint para actualizar la imagen de un producto
app.put('/update-product-image/:id', upload.single('image'), async (req, res) => {
    const productId = req.params.id;
    
    if (!req.file) {
        return res.status(400).json({ error: 'No se ha subido ninguna imagen.' });
    }

    const imageUrl = req.file.path; // Ruta de la imagen cargada

    try {
        // Actualizar la columna de la imagen en la tabla de productos usando Knex
        await knex('products')
            .where({ id: productId })
            .update({ image: imageUrl });

        res.json({ message: 'Imagen actualizada correctamente.', imageUrl });
    } catch (error) {
        console.error('Error al actualizar la imagen:', error);
        res.status(500).json({ error: 'Error al actualizar la imagen del producto.' });
    }
})


// Ruta para cargar la imagen
app.post('/upload', upload.single('image'), (req, res) => {
    // La URL de la imagen será relativa a la raíz del servidor
    const imageUrl = req.file.path;
    // Aquí puedes guardar `imageUrl` en la base de datos con el resto de los datos del producto
    res.json({ imageUrl });
});
// Ruta para servir archivos estáticos (imágenes)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
//endpoint para enviar correo
app.post('/enviar-correo', async (req, res) => {
    const { cliente, productos } = req.body;

    if (!cliente || !cliente.email) {
        return res.status(400).json({ message: 'Se requiere un correo electrónico del cliente' });
    }

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'johaymen.alvarez@gmail.com',
            pass: 'ccdk weot bamt kuvn', // usa variables de entorno en producción
        },
    });

    // Comprobar si hay descuentos aplicados
    const tieneDescuentos = productos.some(producto => producto.descuento > 0);
    let facturaJSON;

    if (tieneDescuentos) {
        const totalSinDescuento = productos.reduce((sum, prod) => sum + prod.price * prod.quantity, 0);
        const totalDescuento = productos.reduce((sum, prod) => sum + prod.descuento, 0);
        const totalConDescuento = totalSinDescuento - totalDescuento;

        facturaJSON = {
            send: true,
            number: 1001,
            prefix: "SETP",
            operation_type_code: "10",
            document_type_code: "01",
            resolution_number: 18760000001,
            date: new Date().toISOString().split('T')[0],
            time: new Date().toLocaleTimeString(),
            currency_type_code: "COP",
            customer: {
                identification_number: cliente.dni,
                dv: 6, // Asigna el valor correcto para "dv"
                name: cliente.name,
                phone: cliente.phone,
                address: cliente.address,
                email: cliente.email,
                merchant_registration: "No tiene",
                identification_type_code: "31",
                language_code: "es",
                organization_type_code: "1",
                country_code: "CO",
                municipality_code: "05001",
                regime_type_code: "49",
                tax_code: "01",
                liability_type_code: "R-99-PN",
            },
            payment_forms: [{
                payment_form_code: "1",
                payment_method_code: "10"
            }],
            allowance_charges: [{
                charge_indicator: false,
                discount_code: "01",
                allowance_charge_reason: "Otro descuento",
                amount: totalDescuento,
                base_amount: totalSinDescuento
            }],
            legal_monetary_totals: {
                line_extension_amount: totalSinDescuento,
                tax_exclusive_amount: 0,
                tax_inclusive_amount: totalSinDescuento,
                allowance_total_amount: totalDescuento,
                charge_total_amount: 0,
                payable_amount: totalConDescuento,
            },
            invoice_lines: productos.map((producto, index) => ({
                unit_measure_code: "94",
                invoiced_quantity: producto.quantity,
                line_extension_amount: producto.price * producto.quantity - producto.descuento,
                free_of_charge_indicator: false,
                description: producto.description,
                code: index + 1,
                item_identification_type_code: "999",
                price_amount: producto.price,
                base_quantity: producto.quantity,
                allowance_charges: [{
                    charge_indicator: false,
                    allowance_charge_reason: "Otro descuento",
                    amount: producto.descuento,
                    base_amount: producto.price
                }]
            })),
        };
    } else {
        const total = productos.reduce((sum, prod) => sum + prod.price * prod.quantity, 0);

        facturaJSON = {
            send: true,
            number: 1001,
            prefix: "SETP",
            operation_type_code: "10",
            document_type_code: "01",
            resolution_number: 18760000001,
            date: new Date().toISOString().split('T')[0],
            time: new Date().toLocaleTimeString(),
            currency_type_code: "COP",
            customer: {
                identification_number: cliente.dni,
                dv: 6, // Asigna el valor correcto para "dv"
                name: cliente.name,
                phone: cliente.phone,
                address: cliente.address,
                email: cliente.email,
                merchant_registration: "No tiene",
                identification_type_code: "31",
                language_code: "es",
                organization_type_code: "1",
                country_code: "CO",
                municipality_code: "05001",
                regime_type_code: "49",
                tax_code: "01",
                liability_type_code: "R-99-PN",
            },
            payment_forms: [{
                payment_form_code: "1",
                payment_method_code: "10"
            }],
            legal_monetary_totals: {
                line_extension_amount: total,
                tax_exclusive_amount: 0,
                tax_inclusive_amount: total,
                allowance_total_amount: 0,
                charge_total_amount: 0,
                payable_amount: total,
            },
            invoice_lines: productos.map((producto, index) => ({
                unit_measure_code: "94",
                invoiced_quantity: producto.quantity,
                line_extension_amount: producto.price * producto.quantity,
                free_of_charge_indicator: false,
                description: producto.description,
                code: index + 1,
                item_identification_type_code: "999",
                price_amount: producto.price,
                base_quantity: producto.quantity,
            })),
        };
    }

    const mailOptions = {
        from: 'johaymen.alvarez@gmail.com',
        to: cliente.email,
        subject: 'Información del Cliente y Productos',
        text: `
            Aquí tienes la información del cliente:
            {
            Nombre: ${cliente.name},
            DNI: ${cliente.dni},
            Dirección: ${cliente.address},
            Teléfono: ${cliente.phone},
            Correo: ${cliente.email}
            }
            Productos comprados:
            [
            ${productos.map((producto, index) => `
                Producto ${index + 1}:
                - Nombre: ${producto.name},
                - Cantidad: ${producto.quantity},
                - Precio Original: ${producto.price},
                - Descuento: ${producto.descuento}
            `).join('\n')}
            ]
            Información de la factura:
            ${JSON.stringify(facturaJSON, null, 2)}
        `,
    };

    try {
        await transporter.sendMail(mailOptions);
        return res.status(200).json({
            message: 'Correo enviado exitosamente',
            cliente: cliente,
            productos: productos,
            factura: facturaJSON
        });
    } catch (error) {
        console.error('Error al enviar el correo:', error);
        return res.status(500).json({ message: 'Error al enviar el correo', error: error.message });
    }
});
app.post('/pagar', passport.authenticate('session'), async (req, res) => {
    const { id_mesa, total_productos, items } = req.body;

    try {
        await knex.transaction(async (trx) => {
            // Obtener el usuario autenticado
            if (!req.isAuthenticated()) {
                throw new Error('No autenticado');
            }

            const { username } = req.user[0];

            // Obtener el id del usuario basado en el username
            const usuario = await trx('usuarios')
                .select('id', 'rol')
                .where('username', username)
                .first();

            if (!usuario) {
                throw new Error('Usuario no encontrado');
            }

            // Obtener el último número de venta para la mesa y sumar 1 para el nuevo pedido
            const lastSaleNumber = await trx('pedidos_mesas')
                .where('id_mesa', id_mesa)
                .max('numero_venta as lastNumeroVenta')
                .first();

            const newNumeroVenta = (lastSaleNumber.lastNumeroVenta || 0) + 1;

            // Calcular el total de la venta
            const total = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

            // Guardar el pedido en `pedidos_mesas`
            await trx('pedidos_mesas').insert({
                id_mesa,
                numero_venta: newNumeroVenta,
                total_productos,
                total: total || 0, // Asegurarse de que el total no sea nulo
                estado: 'pendiente',
                fecha: new Date(),
                productos: JSON.stringify(items),
                usuario_id: usuario.id || null, // Guardar el id del usuario (puede ser nulo)
            });
        });

        res.status(201).json({ message: 'Pedido guardado correctamente' });
    } catch (error) {
        console.error("Error al guardar el pedido:", error);
        res.status(500).json({ message: 'Error al guardar el pedido' });
    }
});

// Endpoint para ventas por día
app.get('/reportes/ventas/dia', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { fecha } = req.query;

        // Validar que se proporcione una fecha
        if (!fecha) {
            return res.status(400).json({ message: 'Debe proporcionar una fecha válida.' });
        }

        // Crear un objeto Moment con la fecha proporcionada
        const startDate = moment(fecha);

        // Verificar si la fecha es válida
        if (!startDate.isValid()) {
            return res.status(400).json({ message: 'Fecha no válida.' });
        }

        // Usar el inicio y el final del día para filtrar las ventas
        const startOfDay = startDate.startOf('day').format('YYYY-MM-DD HH:mm:ss');
        const endOfDay = startDate.endOf('day').format('YYYY-MM-DD HH:mm:ss');

        // Construir la consulta para sumar las ventas y ganancias totales del día
        const resultados = await knex('ventas')
            .where('sale_date', '>=', startOfDay)
            .andWhere('sale_date', '<=', endOfDay)
            .sum('valor_total_compra as total_ventas')  // Suma de las ventas del día
            .sum('ganancia_venta as total_ganancias') // Suma de la ganancia total del día 
            .sum('descuento as descuento_en_ventas') 
            .sum('desc_en_porcentaje as descuento_en_porcentaje')
            .first();

        if (!resultados || resultados.total_ventas === null || resultados.total_ganancias === null) {
            return res.status(404).json({ message: 'No se encontraron ventas en el rango especificado.' });
        }

        // Obtener todas las ventas individuales del día si deseas mostrarlas
        const ventasDelDia = await knex('ventas')
            .select('sale_date', 'total_products', 'usuario_id', 'usuario_rol', 'valor_total_compra', 'ganancia_venta','descuento', 'desc_en_porcentaje')
            .where('sale_date', '>=', startOfDay)
            .andWhere('sale_date', '<=', endOfDay)
            .orderBy('sale_date', 'desc');

        // Responder con las ventas y las sumas de ventas y ganancias
        res.status(200).json({
            total_ventas: resultados.total_ventas,
            total_ganancias: resultados.total_ganancias,
            descuento_en_ventas: resultados.descuento_en_ventas,
            descuento_en_porcentaje: resultados.descuento_en_porcentaje,
            ventas: ventasDelDia
        });

    } catch (error) {
        console.error('Error generando el reporte:', error);
        res.status(500).send('Error interno del servidor');
    }
});


// Endpoint para ventas por semana o entre dos fechas
app.get('/reportes/ventas/rango', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { startDate, endDate } = req.query;

        // Validar que las fechas no estén vacías
        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Debe proporcionar una fecha de inicio y una fecha de fin.' });
        }

        // Validar que las fechas sean correctas
        const startMoment = moment(startDate);
        const endMoment = moment(endDate);

        if (!startMoment.isValid() || !endMoment.isValid()) {
            return res.status(400).json({ message: 'Las fechas proporcionadas son inválidas.' });
        }

        // Formatear las fechas
        const startOfPeriod = startMoment.startOf('day').format('YYYY-MM-DD HH:mm:ss');
        const endOfPeriod = endMoment.endOf('day').format('YYYY-MM-DD HH:mm:ss');

        // Consultar las ventas en el rango de fechas
        const ventas = await knex('ventas')
            .select('sale_date', 'valor_total_compra')
            .whereBetween('sale_date', [startOfPeriod, endOfPeriod])
            .orderBy('sale_date', 'desc');

        if (ventas.length === 0) {
            return res.status(404).json({ message: 'No se encontraron ventas en el rango de fechas especificado.' });
        }

        // Filtrar y convertir a números
        const ventasValidas = ventas
            .filter(venta => venta.valor_total_compra != null) // Filtra valores nulos o indefinidos
            .map(venta => parseFloat(venta.valor_total_compra)) // Asegúrate de que sea un número

        // Calcular la suma total de valor_total_compra
        const totalValorCompras = ventasValidas.reduce((total, venta) => total + venta, 0);

        // Crear respuesta con el total correctamente calculado
        res.json({
            startDate: startOfPeriod,
            endDate: endOfPeriod,
            total: totalValorCompras.toFixed(2) // Formato a 2 decimales
        });
    } catch (error) {
        console.error('Error generando el reporte por rango de fechas:', error);
        res.status(500).send('Error interno del servidor');
    }
});


// Endpoint para ventas por mes
app.get('/reportes/ventas/mes', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { fecha } = req.query;

        // Validar que la fecha no esté vacía
        if (!fecha) {
            return res.status(400).json({ message: 'Debe proporcionar una fecha válida.' });
        }

        const startOfMonth = moment(fecha).startOf('month').format('YYYY-MM-DD HH:mm:ss');
        const endOfMonth = moment(fecha).endOf('month').format('YYYY-MM-DD HH:mm:ss');
        
        // Obtener el total de productos vendidos y el valor total vendido en el mes
        const result = await knex('ventas')
            .select(
                knex.raw('DATE_FORMAT(sale_date, "%Y-%m") AS mes'), // Obtener solo el mes
                knex.raw('SUM(total_products) AS total_productos'), // Sumar todos los productos
                knex.raw('SUM(valor_total_compra) AS valor_total_vendido') // Sumar el valor total de las compras
            )
            .whereBetween('sale_date', [startOfMonth, endOfMonth])
            .groupBy('mes') // Agrupar por mes
            .first(); // Obtener solo una fila

        if (!result) {
            return res.status(404).json({ message: 'No se encontraron ventas en el mes especificado.' });
        }

        res.status(200).json(result);
        console.log(result);
    } catch (error) {
        console.error('Error generando el reporte por mes:', error);
        res.status(500).send('Error interno del servidor');
    }
});
//productos mas y menos vendidos en un rango
app.get('/reportes/ventas/productos', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { startDate, endDate } = req.query;

        // Validar las fechas
        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Debe proporcionar un rango de fechas válido.' });
        }

        // Realiza la consulta para obtener los productos vendidos
        const productosVendidos = await knex.raw(`
            SELECT 
                item.id AS product_id,
                item.name AS product_name,
                SUM(item.quantity) AS total_vendido
            FROM 
                ventas,
                JSON_TABLE(items, '$[*]' COLUMNS (
                    id INT PATH '$.id',
                    name VARCHAR(255) PATH '$.name',
                    quantity INT PATH '$.quantity'
                )) AS item
            WHERE 
                sale_date BETWEEN ? AND ?
            GROUP BY 
                item.id, item.name
            ORDER BY 
                total_vendido DESC
        `, [startDate, endDate]);

        // Verifica si hay resultados
        if (productosVendidos[0].length === 0) {
            return res.status(404).json({ message: 'No se encontraron ventas en el rango especificado.' });
        }

        const maxVendido = productosVendidos[0][0]; // Producto más vendido
        const minVendido = productosVendidos[0][productosVendidos[0].length - 1]; // Producto menos vendido

        res.status(200).json({ maxVendido, minVendido });
    } catch (error) {
        console.error('Error generando el reporte de productos vendidos:', error);
        res.status(500).send('Error interno del servidor');
    }
});

// Ruta para generar la factura en PDF y guardar la venta
app.post('/print-invoice', passport.authenticate('session'), async (req, res) => {
    const trx = await knex.transaction(); // Iniciar transacción

    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado

        // Obtener el id del usuario basado en el username
        const usuario = await knex('usuarios')
            .transacting(trx) // Parte de la transacción
            .select('id', 'username', 'name', 'rol', 'establecimiento_id')
            .where('username', username)
            .first();

        if (!usuario) {
            await trx.rollback(); // Deshacer la transacción si el usuario no existe
            return res.status(404).send('Usuario no encontrado');
        }

        const { usuarioId = usuario.id, usuarioRol = usuario.rol, usuarioEstablecimientoId = usuario.establecimiento_id, cartData, totalCompra, numeroVenta, totalDescuento, desc_en_porcentaje } = req.body;
        
        // Obtener el establecimiento al que pertenece el usuario
        const establecimiento = await knex('establecimientos')
            .transacting(trx) // Parte de la transacción
            .select('name', 'nit', 'address', 'city', 'department','email', 'phone', 'legal_representative')
            .where('id', usuarioEstablecimientoId)
            .first();

        if (!establecimiento) {
            await trx.rollback(); // Deshacer la transacción si el establecimiento no existe
            return res.status(404).send('Establecimiento no encontrado');
        }

        // Obtener los IDs de los productos del carrito
        const productIds = cartData.map((product) => product.id);

        // Consultar los productos habilitados desde la base de datos (IDs positivos)
        const validProducts = await knex('products')
            .transacting(trx) // Parte de la transacción
            .whereIn('id', productIds)
            .andWhere('id', '>', 0); // Filtrar solo productos habilitados (ID positivo)

        // Obtener los IDs de los productos habilitados
        const validProductIds = validProducts.map(product => product.id);

        // Filtrar los productos del carrito que están inhabilitados
        const invalidProducts = cartData.filter(product => !validProductIds.includes(product.id));

        // Validar si todos los productos del carrito están habilitados
        if (invalidProducts.length > 0) {
            await trx.rollback(); // Deshacer la transacción si hay productos inhabilitados
            const invalidProductNames = invalidProducts.map(product => product.name);
            return res.status(400).json({
                message: 'Uno o más productos están inhabilitados.',
                invalidProducts: invalidProductNames
            });
        }

        // Calcular el total de productos
        const totalProducts = cartData.length;

        if (totalProducts <= 0) {
            await trx.rollback(); // Deshacer la transacción si el total de productos es menor o igual a 0
            return res.status(400).json({ message: 'El total de productos debe ser mayor que 0.' });
        }

        // Calcular la ganancia total de la venta
        const gananciaTotalVenta = cartData.reduce((totalGanancia, product) => {
            const gananciaProducto = (product.price - product.price_initial) * product.quantity;
            return totalGanancia + gananciaProducto;
        }, 0);

        // Obtener el último número de venta
        const lastSale = await knex('ventas')
            .transacting(trx) // Parte de la transacción
            .select('numero_venta')
            .orderBy('sale_date', 'desc')
            .first();

        const numero_Venta = lastSale ? lastSale.numero_venta + 1 : 1;

        // Guardar la venta en la base de datos
        await knex('ventas')
        .transacting(trx) // Parte de la transacción
        .insert({
            sale_date: new Date(), // Fecha de la venta
            items: JSON.stringify(cartData), // Detalles de los productos vendidos
            usuario_id: usuarioId, // ID del usuario
            usuario_rol: usuarioRol, // Rol del usuario
            total_products: totalProducts, // Cantidad total de productos vendidos
            valor_total_compra: totalCompra, // Valor total de la compra
            numero_venta: numero_Venta, // Número de venta
            ganancia_venta: gananciaTotalVenta, // Ganancia total de la venta
            descuento: totalDescuento, // Total de descuento aplicado en la venta
            desc_en_porcentaje
        });


        // Actualizar el stock de los productos vendidos
        for (const product of cartData) {
            const { id, quantity } = product;
            const currentStock = await knex('products')
                .transacting(trx) // Parte de la transacción
                .select('stock')
                .where('id', id)
                .first();

            if (currentStock.stock < quantity) {
                await trx.rollback(); // Deshacer la transacción si no hay suficiente stock
                return res.status(400).json({
                    message: `No hay suficiente stock del producto ${product.name}.`
                });
            }

            // Actualizar el stock restando la cantidad vendida
            await knex('products')
                .transacting(trx) // Parte de la transacción
                .where('id', id)
                .update({
                    stock: currentStock.stock - quantity
                });
        }
        
        // Generar el PDF de la factura
        const pdfBuffer = await generateThermalPdf(establecimiento, usuarioId, usuarioRol, cartData, totalProducts);

        // Confirmar (commit) la transacción
        await trx.commit();

        // Enviar el PDF como respuesta
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="invoice.pdf"');
        res.send(pdfBuffer);

    } catch (error) {
        await trx.rollback(); // Deshacer la transacción si hay un error
        console.error('Error generando la factura:', error);
        res.status(500).send('Error interno del servidor');
    }
});

//ultima venta tabla ventas
app.get('/latest-sale-number', async (req, res) => {
    try {
        const lastSale = await knex('ventas')
            .select('numero_venta')
            .orderBy('sale_date', 'desc')
            .first();

        const numeroVenta = lastSale ? lastSale.numero_venta + 1 : 1; // Incrementar o empezar en 1
        res.status(200).json({ numero_venta: numeroVenta });
    } catch (error) {
        console.error('Error al obtener el número de la última venta:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});
//ultima venta tabla pedidos_mesas
app.get('/latest-sale-number-mesas', async (req, res) => {
    try {
        // Obtener el último número de venta de la tabla `pedidos_mesas`
        const lastSale = await knex('pedidos_mesas')
            .select('numero_venta')
            .orderBy('fecha', 'desc') // Asumiendo que 'fecha' es la columna que almacena la fecha del pedido
            .first();

        const numeroVenta = lastSale ? lastSale.numero_venta + 1 : 1; // Incrementar o empezar en 1
        res.status(200).json({ numero_venta: numeroVenta });
    } catch (error) {
        console.error('Error al obtener el número de la última venta:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

//todas las ventas
app.get('/all-sales', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        // Consultar todas las ventas en la base de datos
        const sales = await knex('ventas').select('*');

        if (!sales || sales.length === 0) {
            return res.status(404).send('No se encontraron ventas');
        }

        // Devolver las ventas en formato JSON
        res.json(sales);
    } catch (error) {
        console.error('Error al obtener las ventas:', error);
        res.status(500).send('Error interno del servidor');
    }
});


//Ruta para generar vista previa de pdf
app.post('/view-print-invoice', passport.authenticate('session'), async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).send('No autenticado');
      }
  
      const { username } = req.user[0];
      const usuario = await knex('usuarios')
        .select('id','username', 'rol','establecimiento_id')
        .where('username', username)
        .first();
      if (!usuario) {
        return res.status(404).send('User not found');
      }
  
      const { usuarioId = usuario.id, usuarioRol = usuario.rol, usuarioEstablecimientoId=usuario.establecimiento_id, cartData, totalProducts } = req.body;
      console.log(req.body);
  
      // Obtener el establecimiento al que pertenece el usuario
      const establecimiento = await knex('establecimientos')
        .select('name', 'nit', 'address','city','department', 'phone','email', 'legal_representative')
        .where('id', usuarioEstablecimientoId) // Aquí se asume que tienes el campo establecimiento_id en la tabla usuarios
        .first();
      if (!establecimiento) {
        return res.status(404).send('Company not found');
      }
  
      // Generar el PDF en formato buffer
      const pdfBuffer = await generateThermalPdf(establecimiento, usuarioId, usuarioRol, cartData, totalProducts);
  
      // Convertir el buffer a base64
      const pdfBase64 = pdfBuffer.toString('base64');
  
      // Enviar el PDF en formato base64
      res.json({ pdfBase64 });
    } catch (error) {
      console.error('Error generando la factura:', error);
      res.status(500).send('Internal server error');
    }
  });
    
//Cambiar estado de favoritos
app.patch('/products/:id/favorite', async (req, res) => {
    const productId = req.params.id;
    const { isFavorite } = req.body;

    try {
        await knex('products')
            .where('id', productId)
            .update({ favorito: isFavorite ? 1 : 0 });

        res.status(200).json({ success: true });
    } catch (error) {
        console.error('Error updating favorite status:', error);
        res.status(500).json({ success: false, message: 'Error updating favorite status' });
    }
});
//Consulta para buscar por nombre
app.get('/products/:searchTerm', async (req, res) => {
    const searchTerm = req.params.searchTerm.trim(); // Elimina espacios en blanco innecesarios

    if (!searchTerm) {
        return res.status(400).json({ success: false, message: 'Search term is required' });
    }

    try {
        // Consulta para buscar productos que coincidan con el término de búsqueda
        const products = await knex('products')
            .select('*')
            .where('name', 'like', `%${searchTerm}%`)
            .andWhere('id', '>=', 0); // Buscar productos cuyo nombre contenga el término

        // Devuelve una lista vacía si no hay resultados, en lugar de un 404
        res.status(200).json(products);
    } catch (error) {
        console.error('Error searching products:', error);
        res.status(500).json({ success: false, message: 'Error searching products' });
    }
});


// Endpoint GET para obtener el estado de favorito
app.get('/products/:id/favorite', async (req, res) => {
    const productId = req.params.id;

    try {
        // Consulta el estado de favorito del producto
        const product = await knex('products')
            .select('favorito')
            .where('id', productId)
            .first(); // Usamos first() para obtener un solo resultado

        if (product) {
            // Enviar respuesta con el estado de favorito
            res.status(200).json({ isFavorite: product.favorito === 1 });
        } else {
            // Producto no encontrado
            res.status(404).json({ success: false, message: 'Product not found' });
        }
    } catch (error) {
        console.error('Error fetching favorite status:', error);
        res.status(500).json({ success: false, message: 'Error fetching favorite status' });
    }
});

/*Crear Usuarios
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
});*/
// Endpoint para obtener los datos de la empresa
app.get('/owners/company/:ownerId', passport.authenticate('session'), async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).send('No autenticado');
      }
      const { username } = req.user[0]; // Obtener el username del usuario autenticado
      // Obtener el id del usuario basado en el username
      const owner = await knex('owners')
        .select('id')
        .where('username', username)
        .first();
      if (!owner) {
        return res.status(404).send('User not found');
      }
      const ownerId = owner.id;
      console.log('Owner ID:', ownerId); // Debugging: Verifica el ownerId
      const result = await knex('companies')
        .select('companies.name', 'companies.company_type', 'companies.nit', 'companies.legal_representative')
        .innerJoin('owners', 'owners.id', 'companies.owner_id')
        .where('owners.id', ownerId)
        .first(); // Utiliza .first() si esperas solo un resultado
      if (!result) {
        return res.status(404).send('Company not found');
      }
      res.send(result);
    } catch (error) {
      console.error('Error fetching company data:', error);
      res.status(500).send('Internal server error');
    }
  });
  // Endpoint para obtener los datos de la empresa, relacion muchos a muchos
 app.get('/usuarios/establecimiento/:usuarioId', passport.authenticate('session'), async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).send('No autenticado');
      }
  
      const { username } = req.user[0]; // Obtener el username del usuario autenticado
      // Obtener el id del usuario basado en el username
      const usuario = await knex('usuarios')
        .select('id','username', 'rol')
        .where('username', username)
        .first();
  
      if (!usuario) {
        return res.status(404).send('Usuario no encontrado');
      }
  
      const usuarioId = usuario.id;
      console.log('Usuario ID:', usuarioId); // Debugging: Verifica el usuarioId
  
      // Nueva consulta usando la tabla intermedia
      const result = await knex('establecimientos')
        .select(
          'establecimientos.name',
          'establecimientos.company_type',
          'establecimientos.nit',
          'establecimientos.legal_representative'
        )
        .innerJoin('establecimiento_usuarios', 'establecimientos.id', 'establecimiento_usuarios.establecimiento_id')
        .innerJoin('usuarios', 'usuarios.id', 'establecimiento_usuarios.usuario_id')
        .where('usuarios.id', usuarioId)
        .first(); // Utiliza .first() si esperas solo un resultado
  
      if (!result) {
        return res.status(404).send('Compañía no encontrada');
      }
  
      res.send(result);
    } catch (error) {
      console.error('Error al obtener los datos de la compañía:', error);
      res.status(500).send('Error interno del servidor');
    }
  });
  //consulta para obtener datos establecimiento, relacion uno a muchos
  app.get('/users/establecimiento/:usuarioId', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).send('No autenticado');
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado
        // Obtener el id del usuario basado en el username
        const usuario = await knex('usuarios')
            .select('id', 'username', 'rol', 'establecimiento_id') // Seleccionar establecimiento_id
            .where('username', username)
            .first();

        if (!usuario) {
            return res.status(404).send('Usuario no encontrado');
        }

        const usuarioId = usuario.id;
        const establecimientoId = usuario.establecimiento_id; // Obtener el establecimiento_id

        // Consulta para obtener datos del establecimiento
        const result = await knex('establecimientos')
            .select(
                'establecimientos.name',
                'establecimientos.address',
                'establecimientos.city',
                'establecimientos.department',
                'establecimientos.phone',
                'establecimientos.email',
                'establecimientos.company_type',
                'establecimientos.nit',
                'establecimientos.legal_representative'
            )
            .where('establecimientos.id', establecimientoId) // Filtrar por el establecimiento_id
            .first(); // Utiliza .first() si esperas solo un resultado

        if (!result) {
            return res.status(404).send('Compañía no encontrada');
        }

        res.send(result);
    } catch (error) {
        console.error('Error al obtener los datos de la compañía:', error);
        res.status(500).send('Error interno del servidor');
    }
});

  
//Crear Propietarios
app.post('/owners', async (req, res) => {
    try {
        console.log(req.body);
        const { username, email, password, rol } = req.body;
        const pwd = await bcrypt.hashSync(password, 10);
        const result = await knex('owners').insert({ username, email, password: pwd, rol});
        return res.send(result);
    } catch (error) {
        console.log(error)
        return res.send('ERROR')
    }
});
app.post('/new-user', async (req, res) => {
    try {
        console.log(req.body);
        const { username, name, lastname, email, phone, address, password, rol, establecimiento_id } = req.body;

        // Validaciones
        const existingUser = await knex('usuarios').where({ username }).first();
        const existingEmail = await knex('usuarios').where({ email }).first();
        const existingPhone = await knex('usuarios').where({ phone }).first();

        if (existingUser) {
            return res.status(400).send('El nombre de usuario ya está en uso.');
        }
        if (existingEmail) {
            return res.status(400).send('El correo electrónico ya está en uso.');
        }
        if (existingPhone) {
            return res.status(400).send('El número de teléfono ya está en uso.');
        }

        const pwd = await bcrypt.hashSync(password, 10);
        const result = await knex('usuarios').insert({
            username,
            name,
            lastname,
            email,
            phone,
            address,
            password: pwd,
            rol,
            establecimiento_id
        });

        return res.send(result);
    } catch (error) {
        console.log(error);
        return res.status(500).send('ERROR'); // Cambia el código de estado a 500 en caso de error del servidor
    }
});

//Obetner todos los usuarios
app.get('/all-users', async (req, res) => {
    try {
        // Consulta para obtener todos los productos con unión a la tabla de categorías y ordenar por nombre ascendente
        const result = await knex.select('*').from('usuarios');
        
        // Verifica si se encontraron productos
        if (result.length > 0) {
            return res.status(200).json(result);  // Retorna la lista de todos los productos
        } else {
            return res.status(404).json({ message: 'No se encontraron usuarios' });  // Retorna 404 si no hay productos
        }
    } catch (error) {
        console.error('Error en la consulta de productos:', error);
        return res.status(500).json({ message: 'Error en el servidor' });  // Manejo de errores del servidor
    }
});
//Actualizar usuarios
app.put('/update-users/:id', async (req, res) => {
    const userId = req.params.id;
    const { username, name, lastname, address, phone, email, password, rol } = req.body;

    // Expresión regular para validar el formato del correo electrónico
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        return res.status(400).json({ message: 'El formato del correo electrónico no es válido.' });
    }

    try {
        // Verifica si el email ya existe (excluyendo el usuario actual)
        const existingEmail = await knex('usuarios')
            .where('email', email)
            .andWhere('id', '!=', userId)
            .first();

        if (existingEmail) {
            return res.status(400).json({ message: 'El email ya está en uso por otro usuario.' });
        }

        // Verifica si el username ya existe (excluyendo el usuario actual)
        const existingUsername = await knex('usuarios')
            .where('username', username)
            .andWhere('id', '!=', userId)
            .first();

        if (existingUsername) {
            return res.status(400).json({ message: 'El username ya está en uso por otro usuario.' });
        }

        // Verifica si el phone ya existe (excluyendo el usuario actual)
        const existingPhone = await knex('usuarios')
            .where('phone', phone)
            .andWhere('id', '!=', userId)
            .first();

        if (existingPhone) {
            return res.status(400).json({ message: 'El número de teléfono ya está en uso por otro usuario.' });
        }

        // Actualiza el usuario
        await knex('usuarios')
            .where({ id: userId })
            .update({
                username, name, lastname, address, phone, email, password, rol
            });

        // Obtén el usuario actualizado
        const updatedUser = await knex('usuarios')
            .select('*')
            .where({ id: userId })
            .first();

        if (!updatedUser) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.json(updatedUser); // Envía el usuario actualizado como respuesta
    } catch (error) {
        console.error('Error al actualizar el usuario:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


  //Habilitar o inhabilitar usuarios relacion uno a muchos
  app.put('/disabled-users/:id', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const { username } = req.user[0];

        // Obtener el id del usuario autenticado
        const usuario = await knex('usuarios')
            .select('id', 'rol')
            .where('username', username)
            .first();

        if (!usuario) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const usuarioRol = usuario.rol;

        // Verificar si el rol es "Vendedor"
        if (usuarioRol === 'Vendedor') {
            return res.status(403).json({ success: false, message: 'No autorizado para habilitar o inhabilitar usuarios' });
        }

        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ success: false, message: 'ID inválido.' });
        }

        // Buscar el usuario por su ID
        const userToDisable = await knex('usuarios').where({ id }).first();
        if (!userToDisable) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
        }

        // Iniciar transacción para asegurar que todas las tablas se actualicen correctamente
        await knex.transaction(async (trx) => {
            // Desvincular las ventas
            await trx('ventas')
                .where({ usuario_id: id })
                .update({ usuario_id: null }); // O eliminar si prefieres

            // Cambiar el ID en la tabla usuarios
            await trx('usuarios')
                .where({ id })
                .update({
                    id: -id // Cambiar el ID
                });
        });

        res.json({ success: true, message: 'Usuario actualizado correctamente.' });
    } catch (error) {
        console.error('Error al inhabilitar usuario:', error);
        res.status(500).json({ success: false, message: 'Error al inhabilitar el usuario.' });
    }
});
//Datos del usuario
app.get('/users/:userId', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado
        const user = await knex('usuarios')
            .select('id', 'username', 'rol') // Selecciona los campos que necesites
            .where('username', username)
            .first();

        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        res.json(user); // Devuelve la información del usuario
    } catch (error) {
        console.error('Error al obtener la información del usuario:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

//Crear Clientes
app.post('/new-client', async (req, res) => {
    try {
        console.log(req.body);
        const { name, surname, dni, address, phone, email } = req.body;

        // Validar la estructura del email
        if (!validator.isEmail(email)) {
            return res.status(400).send('El email no tiene un formato válido.');
        }

        // Aquí debes incluir la validación de dni, si ya existe, etc.
        const existingEmail = await knex('customers').where({ email }).first();
        if (existingEmail) {
            return res.status(400).send('El email ya está registrado.');
        }

        const existingDni = await knex('customers').where({ dni }).first();
        if (existingDni) {
            return res.status(400).send('El DNI ya está registrado.');
        }

        const result = await knex('customers').insert({ name, surname, dni, address, phone, email });
        return res.send(result);
    } catch (error) {
        console.log(error);
        return res.status(500).send('ERROR');
    }
});
//Buscar Clientes por Cedula
app.get('/customers/:customerDni', async (req, res) => {
    try {
        const { customerDni } = req.params;
         // Verificar si el cliente existe
         const exists = await knex('customers')
         .select('id') // Solo selecciona un campo para verificar existencia
         .where({ dni: customerDni })
         .first();

        if (!exists) {
            return res.status(404).json({ message: 'Cliente no encontrado' });
        }
        if (exists.id < 0) {
            console.log('Inhabilitado')
            return res.status(400).json({ message: 'Cliente inhabilitado' });
        }
        const result = await knex('customers')
        .select('name', 'surname', 'dni', 'address', 'phone', 'email').where({ dni: customerDni });
        
        if (result.length > 0) {
            return res.json(result[0]); // Devuelve el primer elemento del arreglo
        } else {
            return res.status(404).json({ message: 'Cliente no encontrado' }); // Retorna un mensaje 404 si no hay resultados
        }
    } catch (error) {
        console.error('Error en la consulta de cliente:', error);
        return res.status(500).json({ message: 'Error en el servidor' }); // Devuelve un error 500 si ocurre algún problema
    }
});
//obtener todos los clientes
app.get('/all-customers', async (req, res) => {
    try {
        const { limit } = req.query;
        const result = await knex.select('*').from('customers').orderBy('name', 'asc');;
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});
//Habilitar o inhabilitar clientes
app.put('/disabled-customers/:id', passport.authenticate('session'), async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, message: 'No autenticado' });
      }

      const { username } = req.user[0]; // Obtener el username del usuario autenticado

      // Obtener el id del usuario basado en el username
      const usuario = await knex('usuarios')
        .select('id', 'rol') // Obtener el rol también
        .where('username', username)
        .first();

      if (!usuario) {
        return res.status(404).json({ success: false, message: 'Cliente no encontrado' });
      }

      const usuarioId = usuario.id;
      console.log(usuarioId)
      const usuarioRol = usuario.rol; // Obtener el rol del owner
      console.log(usuarioRol)
      // Verificar si el rol es "Vendedor"
      if (usuarioRol === 'Vendedor') {
        return res.status(403).json({ success: false, message: 'No autorizado para habilitar o inhabilitar cliente' });
      }

      // Convertir id a número
      const id = parseInt(req.params.id, 10);
      // Asegurarse de que es un número válido
      if (isNaN(id)) {
        return res.status(400).json({ success: false, message: 'ID inválido.' });
      }

     
      // Buscar el producto por su ID real (puede ser positivo o negativo)
      const client = await knex('customers').where({ id }).first();
      if (!client) {
        return res.status(404).json({ success: false, message: 'cliente no encontrado.' });
      }

      // Cambiar el ID: Si es positivo, lo hacemos negativo, y viceversa
      const updatedId = id > 0 ? -id : Math.abs(id);
      // Actualizar el ID y el stock
      await knex('customers')
        .where({ id })
        .update({
          id: updatedId,  // Cambia el ID según el estado
        });

      res.json({ success: true, message: 'Cliente actualizado correctamente.' });
    } catch (error) {
      console.error('Error al actualizar cliente:', error);
      res.status(500).json({ success: false, message: 'Error al actualizar el cliente.' });
    }
});
//Actualizar clientes
app.put('/update-customers/:id', async (req, res) => {
    const clientId = req.params.id;
    const { name, surname, dni, address, phone, email } = req.body;
  
    try {
      // Actualiza el cliente
      await knex('customers')
        .where({ id: clientId })
        .update({
            name, surname, dni, address, phone, email
        });
  
      // Obtén el usuario actualizado
      const updatedClient = await knex('customers')
        .select('*')
        .where({ id: clientId })
        .first();
       // broadcastUpdate(updatedProduct);
      if (!updatedClient) {
        return res.status(404).json({ message: 'Cliente no encontrado' });
      }
  
      res.json(updatedClient); // Envía el producto actualizado como respuesta
    } catch (error) {
      console.error('Error al actualizar el cliente:', error);
      res.status(500).json({ message: 'Error en el servidor' });
    }
  });


//Crear Productos
app.post('/new-product', async (req, res) => {
    
    try {
      console.log(req.body);
      const { name, description, price, stock, image, category_id, favorito, price_initial } = req.body;
      const categoryExists = await knex('categories')
      .where({ id: category_id })
      .first();
      if (!categoryExists) {
      return res.status(400).json({ success: false, message: 'La categoría seleccionada no existe.' });
      }
      const result = await knex('products').insert({name, description, price, stock, image, category_id, favorito, price_initial});
      if (result) {
        res.json({ success: true });
      } else {
        res.status(500).json({ success: false, message: 'Error al crear el producto.' });
      }
    } catch (error) {
      console.error('Error al crear producto:', error);
      res.status(500).json({ success: false, message: 'Hubo un error al crear el producto.' });
    }
});
//Habilitar o inhabilitar categorias
app.put('/disabled-categories/:id', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado

        // Obtener el id del usuario basado en el username
        const usuario = await knex('usuarios')
            .select('id', 'rol') // Obtener el rol también
            .where('username', username)
            .first();

        if (!usuario) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const usuarioId = usuario.id;
        const usuarioRol = usuario.rol; // Obtener el rol del owner

        // Verificar si el rol es "Vendedor"
        if (usuarioRol === 'Vendedor') {
            return res.status(403).json({ success: false, message: 'No autorizado para habilitar o inhabilitar categorias' });
        }

        // Convertir id a número
        const id = parseInt(req.params.id, 10);
        // Asegurarse de que es un número válido
        if (isNaN(id)) {
            return res.status(400).json({ success: false, message: 'ID inválido.' });
        }

        // Buscar la categoría por su ID real (puede ser positivo o negativo)
        const category = await knex('categories').where({ id }).first();
        if (!category) {
            return res.status(404).json({ success: false, message: 'Categoria no encontrada.' });
        }

        // Cambiar el ID: Si es positivo, lo hacemos negativo, y viceversa
        const updatedId = id > 0 ? -id : Math.abs(id);

        // Actualizar el ID de la categoría
        await knex('categories')
            .where({ id })
            .update({
                id: updatedId,  // Cambia el ID según el estado
            });

       
        // Si estamos inhabilitando (id > 0 => updatedId negativo)
        if (updatedId > 0) {
            // Inhabilitar productos asociados (poner id en negativo y quitar favoritos)
            await knex('products')
                .where({ category_id: updatedId })  // productos de la categoría actual
                .update({
                    id: knex.raw('ABS(id)')
                    
                });
        } else {
            // Habilitar productos asociados (poner id en positivo)
            await knex('products')
                .where({ category_id: updatedId })  // productos de la categoría actual (deshabilitada)
                .update({
                    id: knex.raw('id * -1'),  // Cambia el ID a negativo
                    favorito: 0            // Si eran favoritos, se deshabilitan // Cambia el ID a positivo
                });
        }

        res.json({ success: true, message: 'Categoria y productos actualizados correctamente.' });
    } catch (error) {
        console.error('Error al actualizar categoria:', error);
        res.status(500).json({ success: false, message: 'Error al actualizar la categoria.' });
    }
});

//Actualizar categorias
app.put('/update-categories/:id', async (req, res) => {
    const categoryId = req.params.id;
    const { name, description } = req.body;
  
    try {
      // Actualiza el usuario
      await knex('categories')
        .where({ id: categoryId })
        .update({
            name, description
        });
  
      // Obtén el usuario actualizado
      const updatedCategory = await knex('categories')
        .select('*')
        .where({ id: categoryId })
        .first();
       // broadcastUpdate(updatedProduct);
      if (!updatedCategory) {
        return res.status(404).json({ message: 'Categoria no encontrado' });
      }
  
      res.json(updatedCategory); // Envía el producto actualizado como respuesta
    } catch (error) {
      console.error('Error al actualizar la categoria:', error);
      res.status(500).json({ message: 'Error en el servidor' });
    }
  });
  
//Habilitar o inhabilitar Productos relacion muchos a muchos
app.put('/disabled-productos/:id', passport.authenticate('session'), async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, message: 'No autenticado' });
      }

      const { username } = req.user[0]; // Obtener el username del usuario autenticado

      // Obtener el id del usuario basado en el username
      const usuario = await knex('usuarios')
        .select('id', 'rol') // Obtener el rol también
        .where('username', username)
        .first();

      if (!usuario) {
        return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
      }

      const usuarioId = usuario.id;
      console.log(usuarioId)
      const usuarioRol = usuario.rol; // Obtener el rol del usuario
      console.log(usuarioRol)
      // Verificar si el rol es "Vendedor"
      if (usuarioRol === 'Vendedor') {
        return res.status(403).json({ success: false, message: 'No autorizado para habilitar o inhabilitar productos' });
      }

      // Convertir id a número
      const id = parseInt(req.params.id, 10);
      // Asegurarse de que es un número válido
      if (isNaN(id)) {
        return res.status(400).json({ success: false, message: 'ID inválido.' });
      }

      const { stock } = req.body;
      // Buscar el producto por su ID real (puede ser positivo o negativo)
      const product = await knex('products').where({ id }).first();
      if (!product) {
        return res.status(404).json({ success: false, message: 'Producto no encontrado.' });
      }

      // Cambiar el ID: Si es positivo, lo hacemos negativo, y viceversa
      const updatedId = id > 0 ? -id : Math.abs(id);
      // Actualizar el ID y el stock
      await knex('products')
        .where({ id })
        .update({
          id: updatedId,  // Cambia el ID según el estado
          stock: stock || product.stock  // Actualizar el stock o mantener el existente
        });

      res.json({ success: true, message: 'Producto actualizado correctamente.' });
    } catch (error) {
      console.error('Error al actualizar producto:', error);
      res.status(500).json({ success: false, message: 'Error al actualizar el producto.' });
    }
});  
  
//Obtener productos favoritos
app.get('/products-favorites', async (req, res) => {
    try {
        // Consulta para obtener los productos favoritos donde la columna 'favorito' es 1
        const result = await knex('products')
            .select('id', 'name', 'description', 'price', 'stock', 'image', 'category_id','favorito', 'price_initial')
            .where({ favorito: 1 }) // Filtra los productos que tienen 'favorito' igual a 1
            .select(
                knex.raw('TRUNCATE(products.price, 0) as price'),
                knex.raw('TRUNCATE(products.price_initial, 0) as price_initial')
              );
        // Verifica si se encontraron productos favoritos
        if (result.length > 0) {
            return res.status(200).json(result);  // Retorna la lista de productos favoritos
        } else {
            return res.status(404).json({ message: 'No se encontraron productos favoritos' });  // Retorna 404 si no hay productos favoritos
        }
    } catch (error) {
        console.error('Error en la consulta de productos favoritos:', error);
        return res.status(500).json({ message: 'Error en el servidor' });  // Manejo de errores del servidor
    }
});
//Actualizar Productos
app.put('/update-products/:id', async (req, res) => {
    const productId = req.params.id;
    const { name, description, price, stock, category_id, favorito, price_initial } = req.body;
  
    try {
      // Actualiza el producto
      await knex('products')
        .where({ id: productId })
        .update({
          name,
          description,
          price,
          stock,
          category_id,
          favorito,
          price_initial
        });
  
      // Obtén el producto actualizado
      const updatedProduct = await knex('products')
        .select('*')
        .where({ id: productId })
        .first();
       // broadcastUpdate(updatedProduct);
      if (!updatedProduct) {
        return res.status(404).json({ message: 'Producto no encontrado' });
      }
  
      res.json(updatedProduct); // Envía el producto actualizado como respuesta
    } catch (error) {
      console.error('Error al actualizar el producto:', error);
      res.status(500).json({ message: 'Error en el servidor' });
    }
  });
  // Función para formatear la fecha al formato MySQL
function formatDateToMySQL(date) {
    const d = new Date(date);
    const year = d.getFullYear();
    const month = ('0' + (d.getMonth() + 1)).slice(-2);
    const day = ('0' + d.getDate()).slice(-2);
    const hours = ('0' + d.getHours()).slice(-2);
    const minutes = ('0' + d.getMinutes()).slice(-2);
    const seconds = ('0' + d.getSeconds()).slice(-2);
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }
  
  // Función para calcular el valor total de la venta basado en los productos
  function calcularValorTotal(items) {
    // Asegurarse de que items es un arreglo
    if (!Array.isArray(items)) {
        items = JSON.parse(items); // Intenta convertir a arreglo si es una cadena
    }

    return items.reduce((total, item) => {
        const price = parseFloat(item.price);
        const quantity = parseInt(item.quantity, 10);
        return total + (price * quantity);
    }, 0);
}

 // Función para calcular el total de productos únicos en la venta
function calcularTotalProductos(items) {
    // Asegurarse de que items es un arreglo
    if (!Array.isArray(items)) {
        items = JSON.parse(items); // Intenta convertir a arreglo si es una cadena
    }

    // Usar un Set para contar productos únicos
    const uniqueProductIds = new Set();

    items.forEach(item => {
        // Agregar el id del producto al Set
        if (item.id) { // Asegúrate de que el item tenga un id
            uniqueProductIds.add(item.id);
        }
    });

    // Devolver la cantidad de productos únicos
    return uniqueProductIds.size; // Retorna la cantidad de productos únicos
}

// Endpoint para actualizar la venta
app.put('/update-sale/:numero_venta', async (req, res) => {
    const numeroVenta = req.params.numero_venta;
    let { sale_date, usuario_id, items } = req.body;

    try {
        // Validar que los campos requeridos están presentes
        if (!sale_date || !usuario_id || !items) {
            return res.status(400).json({ message: 'Faltan campos requeridos en la solicitud' });
        }
        // Asegurarse de que items sea un arreglo
        if (typeof items === 'string') {
            items = JSON.parse(items);
        }

        sale_date = formatDateToMySQL(sale_date);

        // Iniciar la transacción
        await knex.transaction(async (trx) => {
            // Obtener la venta anterior para restaurar el stock y calcular la ganancia
            const previousSale = await trx('ventas')
                .where({ numero_venta: numeroVenta })
                .first();

            if (!previousSale) {
                throw new Error('Venta no encontrada');
            }

            // Parsear los items de la venta anterior
            let previousItems = typeof previousSale.items === 'string' 
                ? JSON.parse(previousSale.items) 
                : previousSale.items;

            // Calcular la ganancia total anterior
            let gananciaAnterior = 0;
            for (const product of previousItems) {
                const currentProduct = await trx('products')
                    .where('id', product.id)
                    .select('price_initial', 'price')
                    .first();

                if (currentProduct) {
                    gananciaAnterior += (currentProduct.price - currentProduct.price_initial) * product.quantity;
                }
            }

            // Restaurar el stock de los productos de la venta anterior
            for (const product of previousItems) {
                const currentStock = await trx('products')
                    .where('id', product.id)
                    .select('stock')
                    .first();

                await trx('products')
                    .where('id', product.id)
                    .update({ stock: currentStock.stock + product.quantity });
            }

            // Verificar si hay suficiente stock para los nuevos productos y calcular la ganancia total
            let gananciaNuevos = 0;
            for (const product of items) {
                const currentProduct = await trx('products')
                    .where('id', product.id)
                    .select('price_initial', 'price', 'stock')
                    .first();

                if (!currentProduct) {
                    throw new Error(`El producto con id ${product.id} no se encontró.`);
                }

                if (currentProduct.stock < product.quantity) {
                    throw new Error(`No hay suficiente stock para el producto ${product.name}.`);
                }

                // Calcular la ganancia para este producto
                const gananciaPorProducto = (currentProduct.price - currentProduct.price_initial) * product.quantity;
                gananciaNuevos += gananciaPorProducto;
            }

            // Calcular la nueva ganancia total
            const nuevaGanancia = gananciaNuevos - gananciaAnterior;

            // Convertir items a JSON si es necesario
            items = typeof items === 'object' ? JSON.stringify(items) : items;

            // Actualizar la venta
            await trx('ventas')
                .where({ numero_venta: numeroVenta })
                .update({
                    sale_date,
                    usuario_id,
                    total_products: calcularTotalProductos(items),
                    valor_total_compra: calcularValorTotal(items),
                    items,
                    ganancia_venta: knex.raw(`ganancia_venta + ${nuevaGanancia}`)
                });

            // Actualizar el stock de los productos con la nueva cantidad
            const updatedItems = JSON.parse(items); // Asegurarse de que items esté en formato objeto
            for (const product of updatedItems) {
                const currentStock = await trx('products')
                    .where('id', product.id)
                    .select('stock')
                    .first();

                await trx('products')
                    .where('id', product.id)
                    .update({ stock: currentStock.stock - product.quantity });
            }
        });

        // Obtener la venta actualizada después de la transacción
        const updatedSale = await knex('ventas')
            .where({ numero_venta: numeroVenta })
            .first();

        res.json(updatedSale); // Enviar la venta actualizada

    } catch (error) {
        console.error('Error al actualizar la venta:', error);
        res.status(500).json({ message: error.message });
    }
});
app.post('/generate-pdf', async (req, res) => {
    const { establecimiento, usuarioId, usuarioRol, cartData, totalProducts } = req.body;
    console.log(establecimiento)

    try {
        const pdfBuffer = await generateThermalPdf(establecimiento, usuarioId, usuarioRol, cartData, totalProducts);
        
        // Establece los encabezados de la respuesta para descargar el archivo PDF
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=factura.pdf');
        res.send(pdfBuffer);
    } catch (error) {
        console.error("Error al generar el PDF:", error);
        res.status(500).send("Error al generar el PDF");
    }
});


//Crear Categorias
app.post('/new-category', async (req, res) => {
    try {
        console.log(req.body);
        const { name, description } = req.body;

        // Verificar si el nombre ya existe en la base de datos
        const existingCategory = await knex('categories').where({ name }).first();
        if (existingCategory) {
            return res.status(400).send('El nombre de la categoría ya está registrado.');
        }

        const result = await knex('categories').insert({ name, description });
        return res.send(result);
    } catch (error) {
        console.log(error);
        return res.status(500).send('ERROR');
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
//Obtener productos por categoria
app.get('/products/category/:categoryId', async (req, res) => {
    try {
        const { categoryId } = req.params;
        const result = await knex
            .select('products.id', 'products.name', 'products.price', 'products.description', 'products.image','products.stock' ,'products.favorito', 'products.price_initial')
            .from('products')
            .join('categories', 'products.category_id', 'categories.id')
            .where('categories.id', categoryId)
            .select(knex.raw('TRUNCATE(products.price, 0) as price'))        
        return res.send(result);
    } catch (error) {
        console.error(error); // Log the error for debugging purposes
        return res.status(500).send('ERROR'); // Send a 500 status code for server errors
    }
});
//Obtener todos los productos
app.get('/all-products', async (req, res) => {
    try {
        // Consulta para obtener todos los productos con unión a la tabla de categorías y ordenar por nombre ascendente
        const result = await knex('products')
            .join('categories', 'products.category_id', '=', 'categories.id') // Unión con la tabla de categorías
            .select('products.id', 'products.name', 'products.description', 'products.price', 'products.stock', 'products.image', 'products.category_id','categories.name as category_name', 'products.favorito', 'products.price_initial') // Selección de campos
            .orderBy('products.name', 'asc') // Ordena los productos por nombre ascendente
            .select(
                knex.raw('TRUNCATE(products.price, 0) as price'),
                knex.raw('TRUNCATE(products.price_initial, 0) as price_initial')
              )
              ; // Trunca el precio
        
        // Verifica si se encontraron productos
        if (result.length > 0) {
            return res.status(200).json(result);  // Retorna la lista de todos los productos
        } else {
            return res.status(404).json({ message: 'No se encontraron productos' });  // Retorna 404 si no hay productos
        }
    } catch (error) {
        console.error('Error en la consulta de productos:', error);
        return res.status(500).json({ message: 'Error en el servidor' });  // Manejo de errores del servidor
    }
});
//obtener producto con stock < 10 und
app.get('/low-stock-products', async (req, res) => {
    try {
        // Consulta para obtener los productos con menos de 10 unidades en stock
        const result = await knex('products')
            .select('id', 'name', 'description', 'stock', knex.raw('TRUNCATE(price, 0) as price')) // Selecciona solo los campos que necesitas
            .where('stock', '<', 10) // Filtra productos con stock menor a 10
            .orderBy('name', 'asc'); // Ordena los productos por nombre ascendente
        
        // Verifica si se encontraron productos
        if (result.length > 0) {
            return res.status(200).json(result);  // Retorna la lista de productos con bajo stock
        } else {
            return res.status(404).json({ message: 'No se encontraron productos con bajo stock' });  // Retorna 404 si no hay productos
        }
    } catch (error) {
        console.error('Error en la consulta de productos con bajo stock:', error);
        return res.status(500).json({ message: 'Error en el servidor' });  // Manejo de errores del servidor
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

/*Obtener Usuarios por Id
app.get('/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await knex.select('username', 'email', 'nationality_id').from('users').where({ id: userId });
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});*/
/*Crear Nacionalidades
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
});*/
//Obtener Caterogias
app.get('/all-categories', async (req, res) => {
    try {
        const { limit } = req.query;
        const result = await knex.select('id', 'name', 'description').from('categories').orderBy('name', 'asc');;
        return res.send(result);
    } catch (error) {
        return res.send('ERROR')
    }
});
//Quitar este endpoint y revisar
app.put('/disable-user/:id', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado

        // Obtener el id del usuario basado en el username
        const usuario = await knex('usuarios')
            .select('id', 'rol')
            .where('username', username)
            .first();

        if (!usuario) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const usuarioRol = usuario.rol;
        if (usuarioRol === 'Vendedor') {
            return res.status(403).json({ success: false, message: 'No autorizado para inhabilitar usuarios' });
        }

        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ success: false, message: 'ID inválido.' });
        }

        // Verificar si el usuario está asociado a un establecimiento
        const association = await knex('establecimiento_usuarios').where({ usuario_id: id }).first();
        if (!association) {
            return res.status(404).json({ success: false, message: 'Usuario no está asociado a ningún establecimiento.' });
        }

        // Eliminar la asociación
        await knex('establecimiento_usuarios').where({ usuario_id: id }).del();

        res.json({ success: true, message: 'Usuario desasociado correctamente.' });
    } catch (error) {
        console.error('Error al desasociar usuario:', error);
        res.status(500).json({ success: false, message: 'Error al desasociar el usuario.' });
    }
});
//Quitar este endpoint y revisar
app.put('/enable-user/:id', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const { username } = req.user[0]; // Obtener el username del usuario autenticado

        // Obtener el id del usuario basado en el username
        const usuario = await knex('usuarios')
            .select('id', 'rol')
            .where('username', username)
            .first();

        if (!usuario) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const usuarioRol = usuario.rol;
        if (usuarioRol === 'Vendedor') {
            return res.status(403).json({ success: false, message: 'No autorizado para habilitar usuarios' });
        }

        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ success: false, message: 'ID inválido.' });
        }

        // Verificar si el usuario ya está asociado a un establecimiento
        const association = await knex('establecimiento_usuarios').where({ usuario_id: id }).first();
        if (association) {
            return res.status(400).json({ success: false, message: 'Usuario ya está asociado a un establecimiento.' });
        }

        // Aquí debes especificar el establecimiento al que deseas asociar al usuario
        const establecimientoId = req.body.establecimientoId;
        if (!establecimientoId) {
            return res.status(400).json({ success: false, message: 'ID de establecimiento es necesario.' });
        }

        // Asociar al usuario con el establecimiento
        await knex('establecimiento_usuarios').insert({
            usuario_id: id,
            establecimiento_id: establecimientoId
        });

        res.json({ success: true, message: 'Usuario asociado correctamente al establecimiento.' });
    } catch (error) {
        console.error('Error al asociar usuario:', error);
        res.status(500).json({ success: false, message: 'Error al asociar el usuario.' });
    }
});
app.get('/api/user-state/:id', passport.authenticate('session'), async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, message: 'No autenticado' });
        }

        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ success: false, message: 'ID inválido.' });
        }

        // Verificar si el usuario está asociado a un establecimiento
        const association = await knex('establecimiento_usuarios').where({ usuario_id: id }).first();
        const isDisabled = !association;

        res.json({ success: true, isDisabled });
    } catch (error) {
        console.error('Error al obtener el estado del usuario:', error);
        res.status(500).json({ success: false, message: 'Error al obtener el estado del usuario.' });
    }
});

app.post('/user-login-v2',async(req, res)=>{
    const body = req.body;
    console.log(body);
    return {
        ok:'funciona'
    }
})
app.post('/new-mesa', async (req, res) => {
    try {
        console.log(req.body); // Verifica lo que llega en el cuerpo de la solicitud
        const { numero_mesa, estado, capacidad } = req.body; // Recibe el número y estado de la mesa

        // Inserta una nueva mesa en la base de datos
        const result = await knex('mesas').insert({ numero_mesa, estado, capacidad });

        // Devuelve la respuesta con la mesa creada
        return res.status(201).send(result);
    } catch (error) {
        console.log(error); // Loguea el error en caso de que ocurra
        return res.status(500).send('ERROR');
    }
});
app.get('/all-mesas', async (req, res) => {
    try {
        // Obtiene todas las mesas desde la base de datos
        const mesas = await knex('mesas').select('*');

        // Envía la lista de mesas como respuesta
        return res.status(200).json(mesas);
    } catch (error) {
        console.log(error); // Loguea cualquier error
        return res.status(500).send('ERROR');
    }
});
// Endpoint para obtener detalles del pedido de una mesa
app.get('/mesas/:mesaId/pedido', async (req, res) => {
    const { mesaId } = req.params;
    try {
        const pedido = await knex('pedidos')
            .where({ id_mesa: mesaId }) // Asegúrate de tener la relación correcta
            .first();

        if (!pedido) {
            return res.status(404).json({ error: 'No se encontró el pedido para esta mesa' });
        }

        return res.status(200).json(pedido);
    } catch (error) {
        console.error('Error al obtener el pedido de la mesa:', error);
        return res.status(500).json({ error: 'Error al obtener el pedido' });
    }
});

app.listen(4001, () => {
    console.log('Listening on port 4001');
   
});


