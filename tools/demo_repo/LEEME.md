# Repositorio de prueba para la línea de órdenes

Dos archivos y una diferencia entre ellos, que es lo que US003 necesita
demostrar sin gastar el corpus entero.

- `vulnerable/UserDao.java` arma la consulta concatenando un parámetro de la
  petición. El analizador lo reporta y el asistente lo declara explotable, de
  modo que `check --fail-on real` sale con código 1 y detendría la entrega.
- `sanitized/OrderDao.java` hace lo mismo con una consulta preparada. No hay
  nada que reportar, y `check` sale con código 0.

Correr `check` sobre el corpus completo serían dos mil ciento sesenta y seis
consultas al modelo. Sobre esta carpeta es una, y demuestra lo mismo: que Certa
corre sin pantalla y que su código de salida sirve para cortar una tubería de
integración continua.
