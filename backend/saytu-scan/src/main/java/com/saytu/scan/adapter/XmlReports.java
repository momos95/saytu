package com.saytu.scan.adapter;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** XML reports (Checkstyle, Cppcheck) parsed with DOCTYPE and external entities disabled. */
final class XmlReports {

    private XmlReports() {
    }

    static Document parse(Path report) throws IOException {
        if (!Files.isRegularFile(report)) {
            throw new IOException("the tool produced no report");
        }
        if (Files.size(report) > AdapterSupport.MAX_REPORT_BYTES) {
            throw new IOException("report too large");
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            return b.parse(report.toFile());
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("unreadable report: " + e.getMessage(), e);
        }
    }

    static Integer intAttr(org.w3c.dom.Element e, String name) {
        String v = e.getAttribute(name);
        if (v == null || v.isEmpty()) {
            return null;
        }
        try {
            int i = Integer.parseInt(v.trim());
            return i >= 1 ? i : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
