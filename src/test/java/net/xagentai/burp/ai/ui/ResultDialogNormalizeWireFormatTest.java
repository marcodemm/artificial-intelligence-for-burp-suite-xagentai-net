package net.xagentai.burp.ai.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultDialogNormalizeWireFormatTest {

    @Test
    void insertsBlankLineBetweenHeadersAndBody() {
        String in  = "GET / HTTP/1.1\nHost: example.com\n";
        String out = ResultDialog.normalizeHttpWireFormat(in);
        assertTrue(out.endsWith("\r\n\r\n"),
                "Headers-only messages must still end with CRLF CRLF so Burp accepts them");
    }

    @Test
    void convertsBareLfToCrlf() {
        String in  = "GET / HTTP/1.1\nHost: example.com\n\nbody";
        String out = ResultDialog.normalizeHttpWireFormat(in);
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody", out);
    }

    @Test
    void preservesAlreadyCorrectMessage() {
        String in  = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nhi";
        String out = ResultDialog.normalizeHttpWireFormat(in);
        assertEquals(in, out, "A well-formed wire message must come back byte-identical");
    }

    @Test
    void preservesBodyLineBreaksAsCrlf() {
        String in  = "POST / HTTP/1.1\nHost: x\n\nline1\nline2";
        String out = ResultDialog.normalizeHttpWireFormat(in);
        assertEquals("POST / HTTP/1.1\r\nHost: x\r\n\r\nline1\r\nline2", out);
    }

    @Test
    void handlesNullAndEmpty() {
        assertEquals("", ResultDialog.normalizeHttpWireFormat(null));
        assertEquals("", ResultDialog.normalizeHttpWireFormat(""));
    }

    @Test
    void stripsTrailingWhitespaceBeforeNormalizing() {
        // Model sometimes emits extra blank lines at the end.
        String in  = "GET / HTTP/1.1\nHost: x\n\n\n\n   ";
        String out = ResultDialog.normalizeHttpWireFormat(in);
        assertEquals("GET / HTTP/1.1\r\nHost: x\r\n\r\n", out);
    }
}
