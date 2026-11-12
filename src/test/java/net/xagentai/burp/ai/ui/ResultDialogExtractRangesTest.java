package net.xagentai.burp.ai.ui;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultDialogExtractRangesTest {

    @Test
    void extractsSingleMarkedPosition() {
        String in = "GET / HTTP/1.1\r\nHost: §foo§\r\n\r\n";
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(in);

        // The cleaned bytes must have the § markers stripped.
        String clean = new String(parsed.contentBytes, StandardCharsets.UTF_8);
        assertEquals("GET / HTTP/1.1\r\nHost: foo\r\n\r\n", clean);

        assertEquals(1, parsed.offsets.size());
        int[] p = parsed.offsets.get(0);
        int fooStart = clean.indexOf("foo");
        assertEquals(fooStart, p[0]);
        assertEquals(fooStart + "foo".length(), p[1]);
    }

    @Test
    void extractsMultipleMarkedPositions() {
        String in = "POST /§one§ HTTP/1.1\r\nX: §two§\r\n\r\n";
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(in);
        assertEquals(2, parsed.offsets.size());
        String clean = new String(parsed.contentBytes, StandardCharsets.UTF_8);
        assertEquals("POST /one HTTP/1.1\r\nX: two\r\n\r\n", clean);
    }

    @Test
    void returnsEmptyRangesWhenNoMarkers() {
        String in = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(in);
        assertEquals(0, parsed.offsets.size());
        assertArrayEquals(in.getBytes(StandardCharsets.UTF_8), parsed.contentBytes);
    }

    @Test
    void dropsUnpairedTrailingMarker() {
        // Odd number of § → the last opening marker is silently dropped.
        String in = "GET / HTTP/1.1\r\nHost: §foo§ bar §baz\r\n\r\n";
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(in);
        assertEquals(1, parsed.offsets.size(),
                "The lone opening § without a pair must not produce a range");
        String clean = new String(parsed.contentBytes, StandardCharsets.UTF_8);
        assertTrue(clean.contains("foo bar baz"),
                "All text (minus the markers themselves) must survive");
    }

    @Test
    void offsetsAreInBytesNotCharsForMultiByteContent() {
        // "café" is 5 bytes in UTF-8 (c=1, a=1, f=1, é=2) but 4 chars in Java.
        String in = "GET / HTTP/1.1\r\nHost: §café§\r\n\r\n";
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(in);
        assertEquals(1, parsed.offsets.size());
        int[] p = parsed.offsets.get(0);
        byte[] prefix = "GET / HTTP/1.1\r\nHost: ".getBytes(StandardCharsets.UTF_8);
        byte[] cafe   = "café".getBytes(StandardCharsets.UTF_8);
        assertEquals(prefix.length, p[0]);
        assertEquals(prefix.length + cafe.length, p[1]);
    }

    @Test
    void handlesNullInput() {
        ResultDialog.ParsedWire parsed = ResultDialog.extractRangesFromMarkers(null);
        assertEquals(0, parsed.offsets.size());
        assertEquals(0, parsed.contentBytes.length);
    }
}
