# PEjector
Pequeño script para inyectar codigo en archivos PE.

El metodo de inyeccion es crear una nueva seccion y Entry Point en "Seccion header" de el archivo, añadiendo la shellcode a la seccion .code

## Uso
El programa recibe 3 argumentos

- -r (ruta del PE)
- -o (ruta donde se guardara el PE)
- -s (shellcode a inyectar)
