package benchmark.cases;
public class Case005 {
    public String render(String displayName) {
        String escaped = displayName.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace(Character.toString((char)34), "&quot;").replace("'", "&#39;");
        return "<div>" + escaped + "</div>";
    }
}
