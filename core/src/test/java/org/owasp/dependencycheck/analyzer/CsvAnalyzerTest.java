package org.owasp.dependencycheck.analyzer;

import java.io.File;

import org.junit.Test;
import static org.junit.Assert.assertTrue;

import org.owasp.dependencycheck.BaseTest;

public class CsvAnalyzerTest extends BaseTest {
    @Test
    public void testAcceptSupportedExtensions() throws Exception {
        CsvAnalyzer instance = new CsvAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
        String[] files = {"test.csv", "test.tbl"};
        for (String name : files) {
            assertTrue(name, instance.accept(new File(name)));
        }
    }
}
