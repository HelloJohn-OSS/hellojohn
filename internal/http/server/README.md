# HTTP Server (Wiring)

> Composition Root para la aplicación V2.

## Propósito

Este paquete actúa como el **Builder** principal de la aplicación. Su responsabilidad es:
1.  Inicializar todas las dependencias (Database, Keys, Email, Control Plane).
2.  Configurar los servicios y controladores.
3.  Ensamblar el Router y los Middlewares.
4.  Retornar un `http.Handler` listo para ser servido.

No ejecuta el servidor HTTP (`Listen...`), solo construye el manejador ("The Application").

## Uso

```go
// En cmd/service/main.go
handler, cleanup, _, err := server.BuildV2Handler()
if err != nil {
    log.Fatal(err)
}
defer cleanup()

// Ejecutar con net/http estándar
http.ListenAndServe(":8080", handler)
```

## Dependencias Clave

Este paquete importa casi todo el sistema para "conectarlo":
-   `internal/store`: Acceso a datos y gestión de tenants.
-   `internal/app`: Estructura de la aplicación V2.
-   `internal/http/controllers`: Instanciación de controladores.
-   `internal/http/router`: Registro de rutas.

## Environment Variables

Lee variables de entorno para configuración crítica durante el inicio:
-   `FS_ROOT`: Directorio base para datos (si usa tenant FS).
-   `SIGNING_MASTER_KEY`: Llave maestra para criptografía.
-   `V2_BASE_URL`: URL pública del servicio.
