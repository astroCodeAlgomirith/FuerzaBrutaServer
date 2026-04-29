package source;
/*
 * package source; // Desde la consola, ejecuta: java -cp
 * .:source/gson-2.13.2.jar source.Server
 * 
 * import com.sun.net.httpserver.Headers; import com.google.gson.Gson; import
 * com.google.gson.GsonBuilder;
 * 
 * import java.util.Map; import java.util.HashMap;
 * 
 * import com.sun.net.httpserver.HttpContext; import
 * com.sun.net.httpserver.HttpServer; import
 * com.sun.net.httpserver.HttpExchange;
 * 
 * import java.io.*; import java.net.InetSocketAddress; import
 * java.net.http.HttpConnectTimeoutException; import java.math.BigInteger;
 * import java.util.ArrayList; import java.util.Arrays; import java.util.List;
 * import java.util.concurrent.Executors;
 * 
 * public class Server { // private static final String TASK_ENDPOINT = "/task";
 * private static final String STATUS_ENDPOINT = "/status"; private static final
 * String SEARCH_TOKEN_ENDPOINT = "/searchtoken"; private static final String
 * ALUMNOS_ENDPOINT = "/alumnos"; // Primero agregamos el endpoint alumnos
 * 
 * private final int port; private HttpServer server; private Map<Integer,
 * Alumno> alumnos = new HashMap<>(); private int currentId = 1;
 * 
 * public static void main(String[] args) throws Exception { int serverPort =
 * 8080; if (args.length == 1) { serverPort = Integer.parseInt(args[0]); }
 * 
 * Server webServer = new Server(serverPort); webServer.startServer();
 * 
 * System.out.println("Server is listenig on port " + serverPort);
 * 
 * }
 * 
 * public Server(int port) { this.port = port; }
 * 
 * public void startServer() { try { this.server = HttpServer.create(new
 * InetSocketAddress("0.0.0.0", port), 0); } catch (IOException e) { // TODO:
 * handle exception e.printStackTrace(); return; } HttpContext statusContext =
 * server.createContext(STATUS_ENDPOINT); // HttpContext taskContext =
 * server.createContext(TASK_ENDPOINT); HttpContext ipnContext =
 * server.createContext("/ipn"); HttpContext searchContext =
 * server.createContext(SEARCH_TOKEN_ENDPOINT); HttpContext dispatcherContext =
 * server.createContext("/dispatcher");
 * dispatcherContext.setHandler(this::handleDispatcherRequest);
 * 
 * HttpContext alumnosContext = server.createContext(ALUMNOS_ENDPOINT);
 * alumnosContext.setHandler(this::handleAlumnosRequest);
 * 
 * statusContext.setHandler(this::handleStatusCheckRequest); //
 * taskContext.setHandler(exchange -> { // try { // handleTaskRequest(exchange);
 * // } catch (Exception e) { // // TODO Auto-generated catch block //
 * e.printStackTrace(); // } // }); server.createContext("/", exchange -> {
 * Map<String, String> error = new HashMap<>(); error.put("error",
 * "Endpoint no encontrado"); String json = new Gson().toJson(error);
 * sendResponse(exchange, 404, json); });
 * 
 * ipnContext.setHandler(this::handleIpnRequest);
 * searchContext.setHandler(this::handleSearchTokenRequest);
 * 
 * server.setExecutor(Executors.newFixedThreadPool(8)); server.start(); }
 * 
 * private void handleAlumnosRequest(HttpExchange exchange) throws IOException {
 * 
 * //Gson gson = new Gson(); Gson gson = new
 * GsonBuilder().setPrettyPrinting().create(); String ruta =
 * exchange.getRequestURI().getPath(); String metodo =
 * exchange.getRequestMethod(); String[] partes = ruta.split("/");
 * 
 * Integer id = null; if (partes.length > 2) { try { id =
 * Integer.parseInt(partes[2]); } catch (Exception e) { Map<String, String>
 * error = new HashMap<>(); error.put("error", "ID invalido");
 * sendResponse(exchange, 400, gson.toJson(error)); return; } }
 * 
 * if (metodo.equalsIgnoreCase("GET")) {
 * 
 * 
 * if (partes.length == 2) { // Si la lista esta vacia if (alumnos.isEmpty()) {
 * sendResponse(exchange, 200, "{}"); } else { sendResponse(exchange, 200,
 * gson.toJson(alumnos.values())); } return; }
 * 
 * if (ruta.equals("/alumnos") || ruta.equals("/alumnos/")) {
 * 
 * Map<String, String> queryParams =
 * queryToMap(exchange.getRequestURI().getQuery());
 * 
 * // seteamos los valores por defecto a la hora de leer los datos int page = 1;
 * int size = 10;
 * 
 * if (queryParams.containsKey("page")) { page =
 * Integer.parseInt(queryParams.get("page")); }
 * 
 * if (queryParams.containsKey("size")) { size =
 * Integer.parseInt(queryParams.get("size")); }
 * 
 * // convertimos a una lista List<Alumno> lista = new
 * ArrayList<>(alumnos.values());
 * 
 * int inicio = (page - 1) * size; int fin = Math.min(inicio + size,
 * lista.size());
 * 
 * if (inicio >= lista.size()) { sendResponse(exchange, 200, "[]"); return; }
 * 
 * List<Alumno> subLista = lista.subList(inicio, fin);
 * 
 * sendResponse(exchange, 200, gson.toJson(subLista)); return; }
 * 
 * 
 * 
 * Alumno alumno = alumnos.get(id);
 * 
 * if (alumno == null) { Map<String, String> error = new HashMap<>();
 * error.put("error", "Alumno no encontrado"); sendResponse(exchange, 404,
 * gson.toJson(error)); return; }
 * 
 * sendResponse(exchange, 200, gson.toJson(alumno)); }
 * 
 * else if (metodo.equalsIgnoreCase("POST")) {
 * 
 * String body = new String(exchange.getRequestBody().readAllBytes());
 * 
 * Alumno alumno = gson.fromJson(body, Alumno.class); alumno.setId(currentId);
 * 
 * alumnos.put(currentId, alumno); currentId++;
 * 
 * sendResponse(exchange, 201, gson.toJson(alumno)); }
 * 
 * else if (metodo.equalsIgnoreCase("PUT")) {
 * 
 * if (!alumnos.containsKey(id)) { Map<String, String> error = new HashMap<>();
 * error.put("error", "Alumno no encontrado"); sendResponse(exchange, 404,
 * gson.toJson(error)); return; }
 * 
 * String body = new String(exchange.getRequestBody().readAllBytes()); Alumno
 * alumno = gson.fromJson(body, Alumno.class); alumno.setId(id);
 * 
 * alumnos.put(id, alumno);
 * 
 * Map<String, String> msg = new HashMap<>(); msg.put("mensaje",
 * "Alumno actualizado");
 * 
 * sendResponse(exchange, 200, gson.toJson(msg)); }
 * 
 * else if (metodo.equalsIgnoreCase("DELETE")) {
 * 
 * if (!alumnos.containsKey(id)) { Map<String, String> error = new HashMap<>();
 * error.put("error", "Alumno no encontrado"); sendResponse(exchange, 404,
 * gson.toJson(error)); return; }
 * 
 * alumnos.remove(id);
 * 
 * exchange.sendResponseHeaders(204, -1); exchange.close(); }
 * 
 * else { exchange.sendResponseHeaders(405, -1); exchange.close(); } }
 * 
 * // QUerremos leer los query params private Map<String, String>
 * queryToMap(String query) { Map<String, String> result = new HashMap<>(); if
 * (query == null) return result;
 * 
 * for (String param : query.split("&")) { String[] pair = param.split("="); if
 * (pair.length > 1) { result.put(pair[0], pair[1]); } } return result; }
 * 
 * // private void handleTaskRequest(HttpExchange exchange)throws Exception{ //
 * if(!exchange.getRequestMethod().equalsIgnoreCase("post")) { //
 * exchange.sendResponseHeaders(405, -1); // Metodo no permitido //
 * exchange.close(); // return; // } // Headers headers =
 * exchange.getRequestHeaders(); // if(headers.containsKey("X-Test") && //
 * headers.get("X-Test").get(0).equalsIgnoreCase("true")) { // String
 * dummyResponse = "123\n"; // sendResponse(dummyResponse.getBytes(), exchange);
 * // return; // } // // boolean isDebugMode = false; //
 * if(headers.containsKey("X-Debug") && //
 * headers.get("X-Debug").get(0).equalsIgnoreCase("true")) { // isDebugMode =
 * true; // } // // long startTime = System.nanoTime(); // // leer datos
 * enviados // byte[] requestBytes = exchange.getRequestBody().readAllBytes();
 * // // // String body = new String(requestBytes); // String[] parts =
 * body.split(","); // Recibe hash objetivo separado por comas // // String
 * hashObjetivo = parts[0]; // char inicioPassword = parts[1].charAt(0); // Lee
 * el caracter // String resultado = "NULL"; // //
 * System.out.println("Hash objetivo: " + hashObjetivo); //
 * System.out.println("Buscando contraseña...\n"); // // for(char a='a'; a<='z';
 * a++){ // for(char b='a'; b<='z'; b++){ // for(char c='a'; c<='z'; c++){ //
 * for(char d='a'; d<='z'; d++) { // String intento = "" + inicioPassword +a + b
 * + c + d; // // String hash = FuerzaBrutaHash.sha256(intento); // //
 * if(hash.equals(hashObjetivo)){ // // resultado =
 * "La contraseña es: "+intento+"\n"; // break; // } // } // } // } // } // //
 * // long finishTIme = System.nanoTime(); // long duration = finishTIme-
 * startTime; // long seconds = duration / 1_000_000_000; // long milliseconds =
 * (duration % 1_000_000_000) / 1_000_000; // // if(isDebugMode) { // String
 * debugMessage = String.format("La operacion tomo %d nanosegundos = %d //
 * segundos con %d milisegundos", duration, seconds, milliseconds); //
 * exchange.getResponseHeaders().put("X-Debug-Info", //
 * Arrays.asList(debugMessage)); // } // byte[] responseBytes =
 * resultado.getBytes(); // exchange.sendResponseHeaders(200,
 * responseBytes.length); // OutputStream os = exchange.getResponseBody(); //
 * os.write(responseBytes); // os.close(); // exchange.close(); // // } private
 * byte[] calculateResponse(byte[] requestBytes) { String bodyString = new
 * String(requestBytes); String[] stringNumbers = bodyString.split(",");
 * BigInteger result = BigInteger.ONE;
 * 
 * for (String number : stringNumbers) { BigInteger bigInteger = new
 * BigInteger(number); result = result.multiply(bigInteger); }
 * 
 * return String.format("Result of the multiplication is %s\n",
 * result).getBytes(); }
 * 
 * private void sendResponse(HttpExchange exchange, int statusCode, String json)
 * throws IOException { exchange.getResponseHeaders().add("Content-Type",
 * "application/json"); byte[] responseBytes = json.getBytes();
 * exchange.sendResponseHeaders(statusCode, responseBytes.length); OutputStream
 * os = exchange.getResponseBody(); os.write(responseBytes); os.close();
 * exchange.close(); }
 * 
 * private String generateRandomToken(int length) { String letters =
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; StringBuilder token = new StringBuilder();
 * 
 * for (int i = 0; i < length; i++) { int index = (int) (Math.random() *
 * letters.length()); token.append(letters.charAt(index)); }
 * 
 * return token.toString(); } private void handleStatusCheckRequest(HttpExchange
 * exchange) throws IOException {
 * if(!exchange.getRequestMethod().equalsIgnoreCase("get")) { exchange.close();
 * return; } String responseMessage = "El servidor esta vivo en el puerto:"+
 * port + "\n"; sendResponse(exchange, 200, responseMessage); }
 * 
 * private void handleIpnRequest(HttpExchange exchange) throws IOException {
 * 
 * if (!exchange.getRequestMethod().equalsIgnoreCase("get")) {
 * exchange.sendResponseHeaders(405, -1); exchange.close(); return; }
 * 
 * Headers headers = exchange.getRequestHeaders(); String userAgent =
 * headers.getFirst("User-Agent");
 * 
 * System.out.println("User-Agent: " + userAgent);
 * 
 * try {
 * 
 * byte[] responseBytes; String contentType;
 * 
 * // Detectar cualquier cliente Java if (userAgent != null &&
 * userAgent.toLowerCase().contains("java")) {
 * 
 * InputStream is = new FileInputStream("src/resources/ascii-ipn.txt");
 * responseBytes = is.readAllBytes(); contentType = "text/plain";
 * 
 * } else { // Si no es cliente java
 * 
 * InputStream is = new FileInputStream("src/resources/ipn.png"); responseBytes
 * = is.readAllBytes(); contentType = "image/png"; }
 * 
 * exchange.getResponseHeaders().add("Content-Type", contentType);
 * exchange.sendResponseHeaders(200, responseBytes.length);
 * 
 * OutputStream os = exchange.getResponseBody(); os.write(responseBytes);
 * os.close();
 * 
 * } catch (Exception e) { e.printStackTrace();
 * exchange.sendResponseHeaders(500, -1); } finally { exchange.close(); } }
 * 
 * private void handleDispatcherRequest(HttpExchange exchange) throws
 * IOException {
 * 
 * if (!exchange.getRequestMethod().equalsIgnoreCase("post")) {
 * exchange.sendResponseHeaders(405, -1); exchange.close(); return; }
 * 
 * long startTime = System.nanoTime();
 * 
 * // lee el hash del cliente String body = new
 * String(exchange.getRequestBody().readAllBytes()); String hashObjetivo =
 * body.trim();
 * 
 * System.out.println("Hash recibido: " + hashObjetivo);
 * 
 * Aggregator aggregator = new Aggregator();
 * 
 * // Genera lista de tareas 26 List<String> listaTareas = new ArrayList<>();
 * 
 * for (char c = 'a'; c <= 'z'; c++) { listaTareas.add(hashObjetivo + "," + c);
 * }
 * 
 * // Lista de direcciones en donde se reciben las tareas List<String> workers =
 * Arrays.asList("http://localhost:8081/task", "http://localhost:8082/task");
 * 
 * List<String> results = aggregator.sendTasksToFreeWorkers(workers,
 * listaTareas);
 * 
 * long endTime = System.nanoTime();
 * 
 * long duration = endTime - startTime; long seconds = duration / 1_000_000_000;
 * long milliseconds = (duration % 1_000_000_000) / 1_000_000;
 * 
 * // XConstruye la respuesta StringBuilder response = new StringBuilder();
 * 
 * response.append("Resultados:\n\n");
 * 
 * for (String r : results) { response.append(r).append("\n"); }
 * 
 * response.append("\nTiempo total: ").append(seconds).append(" segundos con ").
 * append(milliseconds) .append(" ms\n");
 * 
 * byte[] responseBytes = response.toString().getBytes();
 * 
 * exchange.getResponseHeaders().add("Content-Type", "text/plain");
 * exchange.sendResponseHeaders(200, responseBytes.length);
 * 
 * OutputStream os = exchange.getResponseBody(); os.write(responseBytes);
 * os.close(); exchange.close(); }
 * 
 * private void handleSearchTokenRequest(HttpExchange exchange) throws
 * IOException { if (!exchange.getRequestMethod().equalsIgnoreCase("post")) {
 * exchange.sendResponseHeaders(405, -1); exchange.close(); return; }
 * 
 * Headers headers = exchange.getRequestHeaders();
 * 
 * boolean isDebugMode = false; if (headers.containsKey("X-Debug") &&
 * headers.get("X-Debug").get(0).equalsIgnoreCase("true")) { isDebugMode = true;
 * }
 * 
 * long startTime = System.nanoTime();
 * 
 * // leer datos enviados byte[] requestBytes =
 * exchange.getRequestBody().readAllBytes(); String body = new
 * String(requestBytes);
 * 
 * String[] parts = body.split(","); int numTokens = Integer.parseInt(parts[0]);
 * String target = parts[1];
 * 
 * // generar cadena de tokens aleatorios StringBuilder bigString = new
 * StringBuilder();
 * 
 * for (int i = 0; i < numTokens; i++) { String token = generateRandomToken(3);
 * // tokens de 3 letras bigString.append(token); }
 * 
 * String text = bigString.toString();
 * 
 * // buscar subcadena int count = 0; for (int i = 0; i <= text.length() -
 * target.length(); i++) { if (text.substring(i, i +
 * target.length()).equals(target)) { count++; } }
 * 
 * long finishTime = System.nanoTime(); long duration = finishTime - startTime;
 * 
 * long seconds = duration / 1_000_000_000; long milliseconds = (duration %
 * 1_000_000_000) / 1_000_000;
 * 
 * // header debug if (isDebugMode) { String debugMessage = String.
 * format("La operacion tomo %d nanosegundos = %d segundos con %d milisegundos",
 * duration, seconds, milliseconds);
 * exchange.getResponseHeaders().put("X-Debug-Info",
 * Arrays.asList(debugMessage)); }
 * 
 * String response = " el numero de apariciones es " + count + "\n\n";
 * 
 * // String response = "El numero de apariciones es" + count + " ocurrencias de
 * // \"" + target + "\"\n";
 * 
 * exchange.sendResponseHeaders(200, response.getBytes().length); OutputStream
 * os = exchange.getResponseBody(); os.write(response.getBytes()); os.close();
 * exchange.close();
 * 
 * }
 * 
 * }
 */
import com.sun.net.httpserver.Headers;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.http.HttpConnectTimeoutException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.Executors;


public class Server {
	private static final String TASK_ENDPOINT = "/task";
	private static final String STATUS_ENDPOINT = "/status";
	private static final String SEARCH_TOKEN_ENDPOINT ="/searchtoken";
	
	private final int port;
	private HttpServer server;
    public static void main(String[] args) throws Exception {
    	int serverPort = 8080;
		if(args.length == 1) {
			serverPort = Integer.parseInt(args[0]);
		}
		
		Server webServer = new Server(serverPort);
		webServer.startServer();
		
		//System.out.println("Server is listenig on port "+ serverPort);
    	
    }
    public Server(int port) {
		this.port = port;
	}
    
    public void startServer() {
    	try {
    		this.server = HttpServer.create(new InetSocketAddress(port),0);
    	} catch (IOException e) {
			// TODO: handle exception
    		e.printStackTrace();
    		return;
		}
    	HttpContext statusContext = server.createContext(STATUS_ENDPOINT);
    	HttpContext taskContext = server.createContext(TASK_ENDPOINT);
    	HttpContext ipnContext = server.createContext("/ipn");
    	HttpContext searchContext = server.createContext(SEARCH_TOKEN_ENDPOINT);
    	
    	statusContext.setHandler(this::handleStatusCheckRequest);
    	taskContext.setHandler(exchange -> {
			try {
				handleTaskRequest(exchange);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		});
    	ipnContext.setHandler(this::handleIpnRequest);
    	searchContext.setHandler(this::handleSearchTokenRequest);
    	
    	server.setExecutor(Executors.newFixedThreadPool(8));
    	server.start();
    }
    private void handleTaskRequest(HttpExchange exchange)throws Exception{
    	if(!exchange.getRequestMethod().equalsIgnoreCase("post")) {
    		exchange.sendResponseHeaders(405, -1); // Metodo no permitido 
    		exchange.close();
    		return;
    	}
    	Headers headers = exchange.getRequestHeaders();
    	if(headers.containsKey("X-Test") && headers.get("X-Test").get(0).equalsIgnoreCase("true")) {
    		String dummyResponse = "123\n";
    		sendResponse(dummyResponse.getBytes(), exchange);
    		return;
    	}
    	
    	boolean isDebugMode = false;
    	if(headers.containsKey("X-Debug") && headers.get("X-Debug").get(0).equalsIgnoreCase("true")) {
    		isDebugMode = true;
    	}
    	
    	long startTime = System.nanoTime();
    	// leer datos enviados
    	byte[] requestBytes = exchange.getRequestBody().readAllBytes();
    	
    
	    String body = new String(requestBytes);
	    String[] parts = body.split(","); // Recibe hash objetivo separado por comas
	    
	    String hashObjetivo = parts[0];
	    char inicioPassword = parts[1].charAt(0); // Lee el caracter
	    String resultado = "NULL";

        //System.out.println("Hash objetivo: " + hashObjetivo);
        //System.out.println("Buscando contraseña...\n");

		/*
		 * for(char a='a'; a<='z'; a++){ for(char b='a'; b<='z'; b++){ for(char c='a';
		 * c<='z'; c++){ for(char d='a'; d<='z'; d++) { String intento = "" +
		 * inicioPassword +a + b + c + d;
		 * 
		 * String hash = FuerzaBrutaHash.sha256(intento);
		 * 
		 * if(hash.equals(hashObjetivo)){
		 * 
		 * resultado = "La contraseña es: "+intento+"\n"; break; } } } } }
		 */
        for(char a='a'; a<='z'; a++){
            for(char b='a'; b<='z'; b++){
                String intento = "" + inicioPassword + a + b;

                String hash = FuerzaBrutaHash.sha256(intento);

                if(hash.equals(hashObjetivo)){
                    resultado = "La contraseña es: " + intento + "\n";
                    break;
                }
            }
        }

 
    	long finishTIme = System.nanoTime();
    	long duration = finishTIme- startTime;
    	long seconds = duration / 1_000_000_000;
    	long milliseconds = (duration % 1_000_000_000) / 1_000_000;
    	
    	if(isDebugMode) {
    		//String debugMessage = String.format("La operacion tomo %d nanosegundos = %d segundos con %d milisegundos", duration, seconds, milliseconds);
    		//exchange.getResponseHeaders().put("X-Debug-Info", Arrays.asList(debugMessage));
    	}
    	byte[] responseBytes = resultado.getBytes();
    	exchange.sendResponseHeaders(200, responseBytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(responseBytes);
        os.close();
        exchange.close();
    	
    }
	private byte[] calculateResponse(byte[] requestBytes) {
		String bodyString = new String(requestBytes);
		String[] stringNumbers = bodyString.split(",");
		BigInteger result = BigInteger.ONE;
		
		for(String number : stringNumbers) {
			BigInteger bigInteger = new BigInteger(number);
			result = result.multiply(bigInteger);
		}
		
		return String.format("Result of the multiplication is %s\n", result).getBytes();
	}
	private void sendResponse(byte[] responseBytes, HttpExchange exchange) throws IOException {
		exchange.sendResponseHeaders(200, responseBytes.length);
		OutputStream outputStream = exchange.getResponseBody();
		outputStream.write(responseBytes);
		outputStream.flush();
		outputStream.close();
		exchange.close();
		
		
	}
	private String generateRandomToken(int length) {
	    String letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	    StringBuilder token = new StringBuilder();

	    for (int i = 0; i < length; i++) {
	        int index = (int) (Math.random() * letters.length());
	        token.append(letters.charAt(index));
	    }

	    return token.toString();
	}
	private void handleStatusCheckRequest(HttpExchange exchange) throws IOException {
		if(!exchange.getRequestMethod().equalsIgnoreCase("get")) {
    		exchange.close();
    		return;
    	}
		String responseMessage = "El servidor esta vivo en el puerto:"+ port + "\n";
		sendResponse(responseMessage.getBytes(), exchange);
	}
	
	private void handleIpnRequest(HttpExchange exchange) throws IOException {

	    if (!exchange.getRequestMethod().equalsIgnoreCase("get")) {
	        exchange.sendResponseHeaders(405, -1);
	        exchange.close();
	        return;
	    }

	    Headers headers = exchange.getRequestHeaders();
	    String userAgent = headers.getFirst("User-Agent");

	    //System.out.println("User-Agent: " + userAgent);

	    try {

	        byte[] responseBytes;
	        String contentType;

	        // Detectar cualquier cliente Java
	        if (userAgent != null && userAgent.toLowerCase().contains("java")) {

	            InputStream is = new FileInputStream("src/resources/ascii-ipn.txt");
	            responseBytes = is.readAllBytes();
	            contentType = "text/plain";

	        } else { // Si no es cliente java

	            InputStream is = new FileInputStream("src/resources/ipn.png");
	            responseBytes = is.readAllBytes();
	            contentType = "image/png";
	        }

	        exchange.getResponseHeaders().add("Content-Type", contentType);
	        exchange.sendResponseHeaders(200, responseBytes.length);

	        OutputStream os = exchange.getResponseBody();
	        os.write(responseBytes);
	        os.close();

	    } catch (Exception e) {
	        e.printStackTrace();
	        exchange.sendResponseHeaders(500, -1);
	    } finally {
	        exchange.close();
	    }
	}
	
	private void handleSearchTokenRequest(HttpExchange exchange)throws IOException {
		if (!exchange.getRequestMethod().equalsIgnoreCase("post")) {
	        exchange.sendResponseHeaders(405, -1);
	        exchange.close();
	        return;
	    }

	    Headers headers = exchange.getRequestHeaders();

	    boolean isDebugMode = false;
	    if (headers.containsKey("X-Debug") && headers.get("X-Debug").get(0).equalsIgnoreCase("true")) {
	        isDebugMode = true;
	    }

	    long startTime = System.nanoTime();

	    // leer datos enviados
	    byte[] requestBytes = exchange.getRequestBody().readAllBytes();
	    String body = new String(requestBytes);

	    String[] parts = body.split(",");
	    int numTokens = Integer.parseInt(parts[0]);
	    String target = parts[1];

	    // generar cadena de tokens aleatorios
	    StringBuilder bigString = new StringBuilder();

	    for (int i = 0; i < numTokens; i++) {
	        String token = generateRandomToken(3); // tokens de 3 letras
	        bigString.append(token);
	    }

	    String text = bigString.toString();

	    // buscar subcadena
	    int count = 0;
	    for (int i = 0; i <= text.length() - target.length(); i++) {
	        if (text.substring(i, i + target.length()).equals(target)) {
	            count++;
	        }
	    }

	    long finishTime = System.nanoTime();
	    long duration = finishTime - startTime;

	    long seconds = duration / 1_000_000_000;
	    long milliseconds = (duration % 1_000_000_000) / 1_000_000;

	    // header debug
	    if (isDebugMode) {
	        //String debugMessage = String.format(
	                //"La operacion tomo %d nanosegundos = %d segundos con %d milisegundos",
	                //duration, seconds, milliseconds
	        //);
	        //exchange.getResponseHeaders().put("X-Debug-Info", Arrays.asList(debugMessage));
	    }

	    String response = " el numero de apariciones es " + count+ "\n\n";
	    
	    //String response = "El numero de apariciones es" + count + " ocurrencias de \"" + target + "\"\n";

	    exchange.sendResponseHeaders(200, response.getBytes().length);
	    OutputStream os = exchange.getResponseBody();
	    os.write(response.getBytes());
	    os.close();
	    exchange.close();
		
	}
    
    
}
