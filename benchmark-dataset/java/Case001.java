package benchmark.cases;
public class Case001 {
    public String key() {
        String value = System.getenv("BENCHMARK_TEST_API_KEY");
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing configuration");
        }
        return value;
    }
}
