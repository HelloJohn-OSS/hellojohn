// Package dal importa todos los adapters para auto-registro.
// Importar este paquete en main.go para habilitar todos los drivers.
//
// Uso:
//
//	import _ "github.com/dropDatabas3/hellojohn/internal/store/v2/adapters/all"
package dal

import (
	_ "github.com/dropDatabas3/hellojohn/internal/store/adapters/fs"
	_ "github.com/dropDatabas3/hellojohn/internal/store/adapters/mysql"
	_ "github.com/dropDatabas3/hellojohn/internal/store/adapters/pg"
)
