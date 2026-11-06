package com.saytu.core.report;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.Deflater;

/**
 * Small, dependency-free PDF 1.4 writer for text reports: A4 pages, the standard Helvetica, Helvetica-Bold
 * and Courier fonts (WinAnsi encoding, so French accents work without embedding fonts), word wrapping
 * with the Helvetica metrics, compressed content streams, page numbers.
 */
final class PdfDocument {

    static final float PAGE_WIDTH = 595.28f;
    static final float PAGE_HEIGHT = 841.89f;
    static final float MARGIN = 48f;
    static final float CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
    private static final float BOTTOM = MARGIN + 18f;

    enum Font {
        REGULAR("F1", "Helvetica"), BOLD("F2", "Helvetica-Bold"), MONO("F3", "Courier");

        final String resource;
        final String baseFont;

        Font(String resource, String baseFont) {
            this.resource = resource;
            this.baseFont = baseFont;
        }
    }

    /** RGB colour, components 0..1. */
    record Color(float r, float g, float b) {
        static final Color BLACK = new Color(0.11f, 0.14f, 0.16f);
        static final Color MUTED = new Color(0.36f, 0.42f, 0.47f);
        static final Color LINE = new Color(0.85f, 0.87f, 0.89f);

        static Color hex(int rgb) {
            return new Color(((rgb >> 16) & 0xff) / 255f, ((rgb >> 8) & 0xff) / 255f, (rgb & 0xff) / 255f);
        }
    }

    /** Helvetica advance widths (1/1000 em) for ASCII 32..126 (Adobe AFM). */
    private static final short[] HELVETICA = {
            278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
            556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
            1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
            667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
            333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
            556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584};

    private final List<StringBuilder> pages = new ArrayList<>();
    private StringBuilder page;
    private float y;
    private final String footer;

    PdfDocument(String footer) {
        this.footer = footer;
        newPage();
    }

    float y() {
        return y;
    }

    void newPage() {
        page = new StringBuilder(8192);
        pages.add(page);
        y = PAGE_HEIGHT - MARGIN;
    }

    /** Starts a new page when less than {@code height} points remain. */
    void ensure(float height) {
        if (y - height < BOTTOM) {
            newPage();
        }
    }

    void space(float points) {
        y -= points;
    }

    void text(float x, float baseline, Font font, float size, Color color, String text) {
        page.append("BT /").append(font.resource).append(' ').append(num(size)).append(" Tf ")
                .append(num(color.r())).append(' ').append(num(color.g())).append(' ').append(num(color.b())).append(" rg ")
                .append(num(x)).append(' ').append(num(baseline)).append(" Td (");
        for (byte b : encode(text)) {
            int c = b & 0xff;
            if (c == '(' || c == ')' || c == '\\') {
                page.append('\\').append((char) c);
            } else if (c < 32 || c > 126) {
                page.append('\\').append(String.format("%03o", c));
            } else {
                page.append((char) c);
            }
        }
        page.append(") Tj ET\n");
    }

    void rect(float x, float yBottom, float width, float height, Color fill) {
        page.append(num(fill.r())).append(' ').append(num(fill.g())).append(' ').append(num(fill.b())).append(" rg ")
                .append(num(x)).append(' ').append(num(yBottom)).append(' ').append(num(width)).append(' ')
                .append(num(height)).append(" re f\n");
    }

    void rule(Color color) {
        page.append(num(color.r())).append(' ').append(num(color.g())).append(' ').append(num(color.b())).append(" RG 0.5 w ")
                .append(num(MARGIN)).append(' ').append(num(y)).append(" m ").append(num(PAGE_WIDTH - MARGIN)).append(' ')
                .append(num(y)).append(" l S\n");
    }

    /**
     * Writes wrapped text at the cursor, page-breaking as needed.
     *
     * @param maxLines 0 = unlimited; otherwise extra lines are replaced by "…"
     */
    void paragraph(String text, Font font, float size, Color color, float indent, int maxLines) {
        float leading = size * 1.35f;
        List<String> lines = wrap(text, font, size, CONTENT_WIDTH - indent);
        if (maxLines > 0 && lines.size() > maxLines) {
            lines = new ArrayList<>(lines.subList(0, maxLines));
            lines.set(maxLines - 1, lines.get(maxLines - 1) + " …");
        }
        for (String line : lines) {
            ensure(leading);
            y -= leading;
            text(MARGIN + indent, y + size * 0.25f, font, size, color, line);
        }
    }

    /** A table row: each cell wrapped in its column; the row moves to the next page as a whole. */
    void row(String[] cells, float[] widths, Font[] fonts, Color[] colors, float size) {
        float leading = size * 1.35f;
        List<List<String>> wrapped = new ArrayList<>();
        int lines = 1;
        for (int i = 0; i < cells.length; i++) {
            List<String> w = wrap(cells[i] == null ? "" : cells[i], fonts[i], size, widths[i] - 6);
            if (w.size() > 8) {
                w = new ArrayList<>(w.subList(0, 8));
                w.set(7, w.get(7) + " …");
            }
            wrapped.add(w);
            lines = Math.max(lines, w.size());
        }
        float height = lines * leading + 4;
        ensure(height);
        float x = MARGIN;
        for (int i = 0; i < cells.length; i++) {
            float lineY = y;
            for (String line : wrapped.get(i)) {
                lineY -= leading;
                text(x, lineY + size * 0.25f, fonts[i], size, colors[i], line);
            }
            x += widths[i];
        }
        y -= height;
        rule(Color.LINE);
    }

    static float width(String text, Font font, float size) {
        if (font == Font.MONO) {
            return text.length() * 600 * size / 1000f;
        }
        float units = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            int w;
            if (c >= 32 && c <= 126) {
                w = HELVETICA[c - 32];
            } else if (Character.isUpperCase(c)) {
                w = 722;
            } else {
                w = 556;
            }
            units += w;
        }
        // Helvetica-Bold is up to ~20 % wider on narrow letters: over-estimate rather than overflow
        return units * size / 1000f * (font == Font.BOLD ? 1.15f : 1f);
    }

    static List<String> wrap(String text, Font font, float size, float maxWidth) {
        List<String> lines = new ArrayList<>();
        for (String paragraph : text.replace("\r\n", "\n").replace('\r', '\n').replace('\t', ' ').split("\n", -1)) {
            StringBuilder line = new StringBuilder();
            for (String word : paragraph.split(" ", -1)) {
                String candidate = line.isEmpty() ? word : line + " " + word;
                if (width(candidate, font, size) <= maxWidth) {
                    line.setLength(0);
                    line.append(candidate);
                    continue;
                }
                if (!line.isEmpty()) {
                    lines.add(line.toString());
                    line.setLength(0);
                }
                // a word longer than the line (paths, hashes, URLs) is cut
                String rest = word;
                while (width(rest, font, size) > maxWidth) {
                    int cut = Math.max(1, fit(rest, font, size, maxWidth));
                    lines.add(rest.substring(0, cut));
                    rest = rest.substring(cut);
                }
                line.append(rest);
            }
            lines.add(line.toString());
        }
        return lines;
    }

    private static int fit(String text, Font font, float size, float maxWidth) {
        int n = 0;
        while (n < text.length() && width(text.substring(0, n + 1), font, size) <= maxWidth) {
            n++;
        }
        return n;
    }

    /** WinAnsiEncoding (Windows-1252); characters it cannot show become '?'. */
    static byte[] encode(String text) {
        byte[] out = new byte[text.length()];
        int n = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            int code;
            if (c >= 0x20 && c <= 0x7e || c >= 0xa0 && c <= 0xff) {
                code = c;
            } else {
                code = switch (c) {
                    case '€' -> 0x80;
                    case '…' -> 0x85;
                    case '‘' -> 0x91;
                    case '’' -> 0x92;
                    case '“' -> 0x93;
                    case '”' -> 0x94;
                    case '•' -> 0x95;
                    case '–' -> 0x96;
                    case '—' -> 0x97;
                    case 'Œ' -> 0x8c;
                    case 'œ' -> 0x9c;
                    case '→' -> '>';
                    case '◆' -> 0x95;
                    default -> c < 0x20 ? ' ' : '?';
                };
            }
            out[n++] = (byte) code;
        }
        return out;
    }

    byte[] finish(String title, Instant created) {
        int total = pages.size();
        for (int i = 0; i < total; i++) {
            page = pages.get(i);
            text(MARGIN, MARGIN - 14, Font.REGULAR, 7.5f, Color.MUTED, footer);
            String number = "page " + (i + 1) + " / " + total;
            text(PAGE_WIDTH - MARGIN - width(number, Font.REGULAR, 7.5f), MARGIN - 14, Font.REGULAR, 7.5f, Color.MUTED, number);
        }
        Out out = new Out();
        out.raw("%PDF-1.4\n%âãÏÓ\n");
        int fontsStart = 3;
        int infoId = 6;
        int firstPageId = 7;
        List<Integer> offsets = new ArrayList<>();
        offsets.add(out.size());
        out.raw("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets.add(out.size());
        StringBuilder kids = new StringBuilder();
        for (int i = 0; i < total; i++) {
            kids.append(firstPageId + 2 * i).append(" 0 R ");
        }
        out.raw("2 0 obj\n<< /Type /Pages /Kids [" + kids + "] /Count " + total + " >>\nendobj\n");
        for (Font f : Font.values()) {
            offsets.add(out.size());
            out.raw((fontsStart + f.ordinal()) + " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /" + f.baseFont
                    + " /Encoding /WinAnsiEncoding >>\nendobj\n");
        }
        offsets.add(out.size());
        String date = "D:" + DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.ROOT).withZone(ZoneOffset.UTC).format(created) + "Z";
        out.raw(infoId + " 0 obj\n<< /Title " + utf16(title) + " /Producer (SAYTU) /Creator (SAYTU) /CreationDate (" + date
                + ") >>\nendobj\n");
        String resources = "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>";
        for (int i = 0; i < total; i++) {
            int pageId = firstPageId + 2 * i;
            offsets.add(out.size());
            out.raw(pageId + " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + num(PAGE_WIDTH) + " " + num(PAGE_HEIGHT)
                    + "] /Resources " + resources + " /Contents " + (pageId + 1) + " 0 R >>\nendobj\n");
            byte[] content = deflate(pages.get(i).toString().getBytes(StandardCharsets.ISO_8859_1));
            offsets.add(out.size());
            out.raw((pageId + 1) + " 0 obj\n<< /Length " + content.length + " /Filter /FlateDecode >>\nstream\n");
            out.bytes(content);
            out.raw("\nendstream\nendobj\n");
        }
        int xref = out.size();
        StringBuilder x = new StringBuilder("xref\n0 ").append(offsets.size() + 1).append("\n0000000000 65535 f \n");
        for (int offset : offsets) {
            x.append(String.format("%010d 00000 n \n", offset));
        }
        x.append("trailer\n<< /Size ").append(offsets.size() + 1).append(" /Root 1 0 R /Info ").append(infoId)
                .append(" 0 R >>\nstartxref\n").append(xref).append("\n%%EOF\n");
        out.raw(x.toString());
        return out.toByteArray();
    }

    private static String utf16(String s) {
        StringBuilder b = new StringBuilder("<FEFF");
        for (char c : s.toCharArray()) {
            b.append(String.format("%04X", (int) c));
        }
        return b.append('>').toString();
    }

    private static byte[] deflate(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length / 3 + 64);
        byte[] buffer = new byte[8192];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        deflater.end();
        return out.toByteArray();
    }

    private static String num(float f) {
        if (f == Math.rint(f)) {
            return Integer.toString((int) f);
        }
        return String.format(Locale.ROOT, "%.2f", f);
    }

    private static final class Out extends ByteArrayOutputStream {
        void raw(String s) {
            byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
            write(b, 0, b.length);
        }

        void bytes(byte[] b) {
            write(b, 0, b.length);
        }
    }
}
