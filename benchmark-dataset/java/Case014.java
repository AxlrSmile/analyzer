package benchmark.cases;
import java.io.InputStream;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import java.io.IOException;
public class Case014 {
    public Document parse(InputStream input) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(input);
    }
}
