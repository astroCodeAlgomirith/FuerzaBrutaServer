package source;
import com.google.gson.Gson;
import java.util.*;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;

public class GsonAlumno {
    public static void main(String[] args) {

        Gson gson = new Gson();

        // 🔹 Objeto → JSON
        Alumno alumno = new Alumno(1, "Carlos", "Pérez", "Castro", 8.7);
        String jsonAlumno = gson.toJson(alumno);
        System.out.println(jsonAlumno);

        // 🔹 JSON → Objeto
        Alumno alumno2 = gson.fromJson(jsonAlumno, Alumno.class);
        System.out.println(alumno2.getNombre());

        // 🔹 Lista → JSON
        List<Alumno> alumnos = new ArrayList<>();
        alumnos.add(new Alumno(1, "Ana", "Carmona", "Trujillo", 9.1));
        alumnos.add(new Alumno(2, "Luis", "Cuellar", "Paz", 8.5));
        alumnos.add(new Alumno(3, "Carlos", "Pérez", "Castro", 8.7));

        String jsonAlumnos = gson.toJson(alumnos);
        System.out.println(jsonAlumnos);

        // 🔹 JSON → Lista
        Type tipoLista = new TypeToken<List<Alumno>>(){}.getType();
        List<Alumno> alumnos2 = gson.fromJson(jsonAlumnos, tipoLista);

        for (Alumno a : alumnos2) {
            System.out.println(a.getNombre());
        }
    }
}