// utils/pdfUtils.js
const PDFDocument = require('pdfkit');
const fs = require('fs');
const QRCode = require('qrcode');

// Función para generar el PDF en formato de tirilla de 80 mm
const generateThermalPdf = async (establecimiento, usuarioId, usuarioRol, cartData, totalProducts) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: [226, 800], margin: 10 }); // 80mm ≈ 226 puntos en PDFKit
      let buffers = [];
      
      // Guardar en memoria el buffer del PDF
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => {
        const pdfData = Buffer.concat(buffers);
        resolve(pdfData);
      });

      const now = new Date();
      const formattedDate = now.toLocaleDateString(); // formato de fecha
      const formattedTime = now.toLocaleTimeString(); // formato de hora
      const logoPath = 'uploads/1730247552175.jpeg'; // Cambia a la ruta de tu logo
      doc.image(logoPath, { fit: [200, 140], align: 'center', valign: 'top' });
      doc.moveDown(12); 

      // Información de la empresa
      doc
        .fontSize(8)
        .text(`${establecimiento.name}`, { align: 'center' })
        .text(`${establecimiento.nit}`, { align: 'center' })
        .text(`${establecimiento.address}`, { align: 'center' })
        .text(`${establecimiento.city} - ${establecimiento.department}`, { align: 'center' })
        .text(`${establecimiento.phone}`, { align: 'center' })
        .text(`Representante Legal: ${establecimiento.legal_representative}`, { align: 'center' })
        .text(`E-mail: ${establecimiento.email}`, { align: 'center' })
        .moveDown(0.5);
      doc
        .fontSize(8)
        .text('FACTURA ELECTRÓNICA DE VENTA', { align: 'center' })
        .fontSize(8)
        .text(`Fecha creación de factura: ${formattedDate}`, { align: 'center' })  // Agregar fecha
        .text(`Hora creación de factura: ${formattedTime}`, { align: 'center' })   // Agregar hora
        .moveDown(2);

      // Información del cliente
      doc
        .text(`Venta Número: ${cartData[0].numero_venta}`)
        .text(`ID Usuario: ${usuarioId}`)
        .text(`Rol: ${usuarioRol}`)
        .moveDown(1.5);

      // Detalles de la compra
      doc.text('Detalles de la compra:', { align: 'left' });
      const tableTop = doc.y + 5;

      // Encabezados de la tabla
      doc
        .fontSize(8)
        .text('Cant.', 10, tableTop)
        .text('Artículo', 40, tableTop)
        .text('P.Unit', 120, tableTop)
        .text('Total', 180, tableTop)
        .moveDown(0.5);

      // Agregar los productos
      let position = tableTop + 15;
      cartData.forEach(product => {
        doc
          .text(product.quantity, 10, position)
          .text(product.name, 40, position, { width: 70, ellipsis: true }) // Ajuste para nombres largos
          .text(`$${product.price}`, 120, position)
          .text(`$${product.quantity * product.price}`, 180, position);
        position += 12;
      });

      const totalUnidades = cartData.reduce((acc, product) => acc + product.quantity, 0);
      // Total de la factura
      position += 10;
      doc
        .fontSize(8)
        .text(`Total items: ${totalProducts}`, 10, position)
        .text(`Total de unidades vendidas: ${totalUnidades}`, 10, position + 12)
        .text(`Total a pagar: $${cartData.reduce((acc, product) => acc + (product.quantity * product.price), 0)}`, 10, position + 24, { align: 'right' });

      // Pie de página
      doc
        .moveDown(1)
        .text('Gracias por su compra.', { align: 'center' });

      // Generar el contenido para el código QR
      let productsInfo = cartData.map(product => {
        return `${product.name} - Cantidad: ${product.quantity} - Precio: $${product.price}`;
      }).join(' | '); // Concatenar los productos con un separador

      // Genera el código QR con la información de los productos
      QRCode.toDataURL(productsInfo)
        .then(qrDataUrl => {
          // Cálculo de la posición actual para agregar el código QR

          // Agrega el código QR en la parte inferior de la factura
          doc.image(Buffer.from(qrDataUrl.split(",")[1], 'base64'), { fit: [200, 80], align: 'center', valign: 'top' });

          doc
          .moveDown(12)
          .text('Generado por Sinsa-Eccommerce.', { align: 'center' })
          .text('Nit: 98765431-0', { align: 'center' })
          .text('www.sinsaerp.com', { align: 'center' })
          .text('Sincelejo - Sucre.', { align: 'center' });
          // Finalizar el PDF
          doc.end();
        })
        .catch(error => {
          reject(error);
        });

    } catch (error) {
      reject(error);
    }
  });
};

module.exports = { generateThermalPdf };




