package org.owasp.dependencycheck.analyzer;

import java.io.File;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

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

    @Test
    public void testSimple() throws Exception {
        Engine engine = new Engine(getSettings());
        Dependency dep = new Dependency(BaseTest.getResourceAsFile(this, "csv/dependencies.csv"));
        CsvAnalyzer instance = new CsvAnalyzer();
        instance.initialize(getSettings());
        instance.analyze(dep, engine);
        Dependency[] dependencies = engine.getDependencies();
        assertEquals("number of dependencies should be 1", 1, dependencies.length);
    }
}
