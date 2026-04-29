package source;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Application {

    private static final String WORKER_ADDRESS_1 = "http://localhost:8081/task";
    private static final String WORKER_ADDRESS_2 = "http://localhost:8082/task";

    public static void main(String[] args) throws Exception {

        Aggregator aggregator = new Aggregator();

        String password = "carro";
        String hash = sha256(password);

        List<String> listaTareas = new ArrayList<>();

        // Generar 26 tareas
        for (char c = 'a'; c <= 'z'; c++) {
            listaTareas.add(hash + "," + c);
        }

        // 🔥 1. IMPRIMIR LISTA DE TAREAS
        System.out.println("Las tareas a resolver son las siguientes:");
        int index = 0;
        for (String tarea : listaTareas) {
            System.out.println("Tarea " + index + ": " + tarea);
            index++;
        }

        System.out.println();

        // 🔥 2. EJECUTAR
        List<String> results = aggregator.sendTasksToFreeWorkers(
                Arrays.asList(WORKER_ADDRESS_1, WORKER_ADDRESS_2),
                listaTareas
        );

        // 🔥 3. IMPRIMIR RESULTADOS PARCIALES
        //System.out.println("\n===== RESULTADOS =====");

        for (String result : results) {
            System.out.println(result);
        }
    }

    public static String sha256(String texto) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(texto.getBytes());

        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}