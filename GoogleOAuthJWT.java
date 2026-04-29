package source;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Scanner;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class GoogleOAuthJWT {
	public static void main(String[] args) throws Exception {
		
		Scanner scanner = new Scanner(System.in);
		System.out.print("Escribe el nombre del bucket: ");
	    String bucket = scanner.nextLine();
	    System.out.print("Escribe el nombre del archivo a descargar: ");
	    String recurso = scanner.nextLine();
	    
		

        // 1. Leer JSON credentials
        String json = new String(Files.readAllBytes(Paths.get("source/credentials.json")));

        JsonObject creds = JsonParser.parseString(json).getAsJsonObject();

        String clientEmail = creds.get("client_email").getAsString();
        String privateKeyPem = creds.get("private_key").getAsString();
        String tokenUri = creds.get("token_uri").getAsString();

        // 2. Limpiar clave privada PEM
        privateKeyPem = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
        
        

        // 3. Crear Header JWT
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String header = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));

        // 4. Crear Payload JWT
        long now = Instant.now().getEpochSecond();

        String payloadJson = "{"
                + "\"iss\":\"" + clientEmail + "\","
                + "\"scope\":\"https://www.googleapis.com/auth/devstorage.read_only\","
                + "\"aud\":\"" + tokenUri + "\","
                + "\"exp\":" + (now + 3600) + ","
                + "\"iat\":" + now
                + "}";

        String payload = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        // 5. Firmar JWT
        String unsignedToken = header + "." + payload;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(unsignedToken.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();

        String jwt = unsignedToken + "." + base64UrlEncode(signed);

        // 6. Enviar a OAuth token endpoint
        String requestBody = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                + "&assertion=" + jwt;

        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JsonObject jsonResponse = JsonParser.parseString(response.body()).getAsJsonObject();
        String accessToken = jsonResponse.get("access_token").getAsString();
        System.out.println("Bucket: [" + bucket + "]");
        System.out.println("Recurso: [" + recurso + "]");
        
        HttpRequest descargarRecursoRequest = HttpRequest.newBuilder()
                .uri(URI.create("https://storage.googleapis.com/storage/v1/b/" 
                    + bucket + "/o/" + URLEncoder.encode(recurso, StandardCharsets.UTF_8) + "?alt=media"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
       
        HttpResponse<byte[]> responseDescarga = client.send(
        	    descargarRecursoRequest,
        	    HttpResponse.BodyHandlers.ofByteArray()
        	);
        Files.write(Paths.get(recurso), responseDescarga.body());

        // 7. Mostrar respuesta
        System.out.println("Respuesta Auth:");
        System.out.println(response.statusCode());
        System.out.println("Respuesta Descarga:");
        System.out.println(responseDescarga.statusCode());
        scanner.close();
    }
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

    private static String base64UrlEncode(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
}