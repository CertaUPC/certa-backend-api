"""El enmascarado de literales decide dónde empieza y acaba cada método.

Se sustituyen cadenas, caracteres y comentarios por espacios antes de contar
llaves. Si el enmascarado se equivoca, el conteo se descuadra y un método se
traga a los que vienen detrás: el contexto que se le manda al modelo pasa a ser
medio archivo, o peor, se pierden los métodos siguientes y no se recuperan sus
cuerpos aunque el dato pase por ellos.
"""

from src.finding_validation.infrastructure.external import (
    java_source_scanner as scanner,
)

# La barra doble de una URL dentro de una cadena tiene la misma forma que el
# comienzo de un comentario de línea.
#
# Van varias cadenas detrás, como en el archivo real del conjunto de
# referencia: el desemparejado avanza línea a línea, y hace falta que llegue a
# tapar la llave que cierra el método para que el daño se note. Con una sola
# cadena detrás el conteo todavía cuadra por casualidad.
CON_URL = '''class C {

    protected void configurar() {
        env.put(Context.PROVIDER_URL, "ldap://localhost:10389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secreto");
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.LdapCtxFactory");
    }

    public boolean insertar(Persona p) {
        return true;
    }

    private boolean buscar(Persona p) {
        return false;
    }
}
'''


class TestMasking:
    """Se comprueba el enmascarado en sí, no el conteo de llaves que viene
    después.

    Que un enmascarado roto llegue a tragarse una llave depende de cuántas
    comillas queden desemparejadas más abajo, es decir, de la suerte. Una prueba
    apoyada en ese síntoma pasa o falla según el archivo de ejemplo y no dice
    nada. Lo que se exige aquí es lo que el enmascarado promete: fuera literales
    y comentarios, intacto todo lo demás.
    """

    @staticmethod
    def linea(fuente: str, n: int) -> str:
        return scanner._blank_out_literals(fuente).splitlines()[n - 1]

    def test_a_url_inside_a_string_does_not_open_a_comment(self):
        """La barra doble de una URL tiene la misma forma que un comentario.

        Si se toma por tal, se borra el resto de la línea con la comilla de
        cierre incluida. Esa comilla queda emparejada con otra de más abajo, y
        desde ahí se enmascara código de verdad, llaves incluidas.
        """
        assert self.linea(CON_URL, 4).rstrip().endswith(");"), (
            "el cierre de la llamada se perdió: la URL se tomó por comentario"
        )

    def test_the_string_itself_is_masked(self):
        assert "localhost" not in self.linea(CON_URL, 4)

    def test_code_after_the_string_survives_on_every_line(self):
        for n in range(4, 9):
            assert self.linea(CON_URL, n).rstrip().endswith(");"), (
                f"la línea {n} quedó mutilada por el enmascarado"
            )

    def test_the_closing_brace_survives(self):
        assert self.linea(CON_URL, 9).strip() == "}"

    def test_methods_after_the_url_are_still_found(self):
        metodos = {m.name: m for m in scanner.find_methods(CON_URL)}
        assert set(metodos) == {"configurar", "insertar", "buscar"}
        assert metodos["configurar"].end_line < metodos["insertar"].start_line

    def test_a_real_line_comment_is_still_masked(self):
        fuente = '''class C {
    void a() {
        // esto no cuenta: {
    }
    void b() { }
}'''
        assert {m.name for m in scanner.find_methods(fuente)} == {"a", "b"}

    def test_a_brace_inside_a_string_is_still_masked(self):
        fuente = '''class C {
    void a() {
        String s = "una llave suelta: {";
    }
    void b() { }
}'''
        assert {m.name for m in scanner.find_methods(fuente)} == {"a", "b"}

    def test_a_quote_inside_a_comment_does_not_open_a_string(self):
        fuente = '''class C {
    void a() {
        // no es una comilla de verdad: "
        int x = 1;
    }
    void b() { }
}'''
        assert {m.name for m in scanner.find_methods(fuente)} == {"a", "b"}

    def test_masking_keeps_the_length(self):
        """Los índices del texto enmascarado se usan sobre el original."""
        for fuente in (CON_URL, 'class C { String s = "a//b"; }'):
            assert len(scanner._blank_out_literals(fuente)) == len(fuente)
