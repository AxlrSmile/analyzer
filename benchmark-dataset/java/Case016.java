package benchmark.cases;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
public class Case016 {
    public String fetch(HttpClient client, String itemId) throws IOException, InterruptedException {
        String encoded = URLEncoder.encode(itemId, StandardCharsets.UTF_8);
        URI uri = URI.create("https://api.example.invalid/v1/items/" + encoded);
        HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
