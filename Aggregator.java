package source;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;

public class Aggregator {

    private WebClient webClient;

    public Aggregator() {
        this.webClient = new WebClient();
    }

    public List<String> sendTasksToFreeWorkers(List<String> workersAddresses, List<String> tasks) {

        int numWorkers = workersAddresses.size();
        CompletableFuture<String>[] futures = new CompletableFuture[numWorkers];

        List<String> results = new ArrayList<>();

        int nextTaskIndex = 0;
        boolean found = false;

        //  Asignar primeras tareas
        for (int i = 0; i < numWorkers; i++) {
            String worker = workersAddresses.get(i);
            String task = tasks.get(nextTaskIndex);

            futures[i] = webClient.sendTask(worker, task.getBytes());

            System.out.println("Asignando tarea " + task + " al servidor " + worker);

            nextTaskIndex++;
        }

        //  Procesamiento dinámico
        while (!found && nextTaskIndex <= tasks.size()) {

            for (int i = 0; i < numWorkers; i++) {

                if (futures[i].isDone()) {

                    try {
                        String result = futures[i].get();

                        // Guardar resultado con su tarea correcta
                        String tarea = tasks.get(nextTaskIndex - numWorkers + i);
                        String linea = "Para la tarea " + tarea + " " + result;

                        results.add(linea);

                        System.out.println("Servidor " + workersAddresses.get(i) + " respondió: " + result);

                        // 
                        if (!result.equals("NULL")) {
                            found = true;
                            System.out.println("\nel resultado fue: " + result);
                            break;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    // Asignar nueva tarea  si no se encontró
                    if (!found && nextTaskIndex < tasks.size()) {

                        String newTask = tasks.get(nextTaskIndex);

                        System.out.println("Asignando tarea " + newTask + " al servidor " + workersAddresses.get(i));

                        futures[i] = webClient.sendTask(workersAddresses.get(i), newTask.getBytes());

                        nextTaskIndex++;
                    }
                }
            }

            if (found) {
                break;
            }
        }

        return results;
    }
}