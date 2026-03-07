# Utilities

> Funciones auxiliares y herramientas comunes.

## Componentes

### 1. `MaskEmail` (`mask.go`)

Ofusca direcciones de correo electrónico para logs o respuestas públicas, manteniendo el formato básico pero ocultando la identidad.

-   `juanperon@argentina.gob.ar` -> `j…n@a…a.gob.ar`
-   Cortos: `abc@d.com` -> `a…c@d.com`
-   Muy cortos: `a@b.c` -> `***`

### 2. `AtomicWriteFile` (`atomicwrite/`)

Escritura atómica de archivos resistente a fallos y compatible con Windows.

-   **Estrategia**: Escribe en un archivo temporal (`.tmp-*`), hace `fsync` y luego renombra.
-   **Windows-Safe**: Si el rename falla (común en Windows si el archivo destino existe o está bloqueado), intenta borrar el destino y reintentar el renombrado, minimizando la ventana de inconsistencia.
