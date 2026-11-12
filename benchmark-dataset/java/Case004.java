package benchmark.cases;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
public class Case004 {
    public String fetch(HttpClient client, String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
