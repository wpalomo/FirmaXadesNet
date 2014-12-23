FirmaXadesNet
=============

INTRODUCCIÓN
-------------
FirmaXadesNet es una librería desarrollada en C# para la generación de firmas XADES realizada por el Dpto. de Nuevas Tecnologías de la Concejalía de Urbanismo del Ayuntamiento de Cartagena, la cual está basada en una modificación del XADES starter kit desarrollado por Microsoft Francia.


CARACTERÍSTICAS
---------------

- Generación de firmas XADES-BES, XADES-T y XADES-XL.

- Formatos Externally Detached, Internally Detached, Enveloped y Enveloping.

- Validación de certificados mediante OCSP.

- Sellado de tiempo.

Adicionalmente permite cargar archivos de firma para su posterior ampliación a XADES-T o XADES-XL, con esta funcionalidad podremos hacer que nuestra aplicación de escritorio permita al usuario firmar con su certificado, y posteriormente podemos ampliar dicha firma mediante un servicio web en ASP.NET.

Las pruebas han sido realizadas con el certificado del DNI-e y con la tarjeta criptográfica de la ACCV.

La documentación se encuentra actualmente en fase de desarrollo, pero dentro de la solución se encuentra un proyecto con ejemplos de uso de la librería. El ejemplo incluido hace uso del servidor de sellado de tiempo de la ACCV.
