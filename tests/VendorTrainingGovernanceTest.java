import java.nio.file.Files;
import java.nio.file.Path;

/** Verifies that draft/deprecated training rules cannot affect parsing. */
public class VendorTrainingGovernanceTest {
    public static void main(String[] args) throws Exception {
        Path map = VendorTrainingMap.MAP_PATH;
        String original = Files.exists(map) ? Files.readString(map) : null;
        try {
            Files.createDirectories(map.getParent());
            Files.writeString(map, "{\"entries\":["
                + "{\"vendor\":\"Cisco\",\"pattern\":\"draft-only-command\",\"status\":\"draft\"},"
                + "{\"vendor\":\"Cisco\",\"pattern\":\"approved-command\",\"status\":\"active\"},"
                + "{\"vendor\":\"Cisco\",\"pattern\":\"legacy-command\"}"
                + "]}");
            VendorTrainingMap.reload();
            if (VendorTrainingMap.findMatch("Cisco", "draft-only-command") != null) {
                throw new AssertionError("draft rule became executable");
            }
            if (VendorTrainingMap.findMatch("Cisco", "approved-command") == null) {
                throw new AssertionError("approved rule was not loaded");
            }
            if (VendorTrainingMap.findMatch("Cisco", "legacy-command") == null) {
                throw new AssertionError("legacy active rule compatibility broke");
            }
            System.out.println("VendorTrainingGovernanceTest passed");
        } finally {
            if (original == null) Files.deleteIfExists(map);
            else Files.writeString(map, original);
            VendorTrainingMap.reload();
        }
    }
}
