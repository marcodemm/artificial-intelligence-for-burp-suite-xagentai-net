package net.xagentai.burp.ai.ui;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultDialogParseTestBlocksTest {

    @Test
    void parsesSingleBlock() {
        String out =
                "Here is the test:\n\n"
              + "=== TEST: Host header reflection ===\n"
              + "GET / HTTP/1.1\n"
              + "Host: evil.example\n"
              + "\n"
              + "=== END TEST ===\n"
              + "\nSome prose after.";
        List<ResultDialog.TestBlock> parsed = ResultDialog.parseTestBlocks(out);
        assertEquals(1, parsed.size());
        assertEquals("Host header reflection", parsed.get(0).name);
        assertTrue(parsed.get(0).body.startsWith("GET / HTTP/1.1"));
        assertTrue(parsed.get(0).body.contains("Host: evil.example"));
    }

    @Test
    void parsesMultipleContiguousBlocks() {
        String out =
                "=== TEST: a ===\n"
              + "GET /a HTTP/1.1\nHost: x\n\n\n"
              + "=== END TEST ===\n"
              + "=== TEST: b ===\n"
              + "GET /b HTTP/1.1\nHost: y\n\n\n"
              + "=== END TEST ===\n";
        List<ResultDialog.TestBlock> parsed = ResultDialog.parseTestBlocks(out);
        assertEquals(2, parsed.size());
        assertEquals("a", parsed.get(0).name);
        assertEquals("b", parsed.get(1).name);
    }

    @Test
    void ignoresUnclosedBlock() {
        String out = "=== TEST: forgot the end ===\nGET / HTTP/1.1\nHost: x\n\n\n";
        assertTrue(ResultDialog.parseTestBlocks(out).isEmpty(),
                "A block without '=== END TEST ===' must be ignored, not half-returned");
    }

    @Test
    void returnsEmptyForNullOrBlank() {
        assertTrue(ResultDialog.parseTestBlocks(null).isEmpty());
        assertTrue(ResultDialog.parseTestBlocks("").isEmpty());
        assertTrue(ResultDialog.parseTestBlocks("   \n\n  ").isEmpty());
    }

    @Test
    void trimsWhitespaceFromNameAndBody() {
        String out = "=== TEST:   padded  ===\n  \nGET / HTTP/1.1\nHost: x\n\n\n  \n=== END TEST ===\n";
        List<ResultDialog.TestBlock> parsed = ResultDialog.parseTestBlocks(out);
        assertEquals(1, parsed.size());
        assertEquals("padded", parsed.get(0).name,
                "Leading/trailing whitespace around the name must be trimmed");
        assertTrue(parsed.get(0).body.startsWith("GET / HTTP/1.1"),
                "Leading blank lines in the body must be trimmed");
    }
}
