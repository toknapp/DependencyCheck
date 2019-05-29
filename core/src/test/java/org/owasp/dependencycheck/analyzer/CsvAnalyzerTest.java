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
    public void testSimple() throws Exception {
        Engine engine = new Engine(getSettings());
        Dependency dep = new Dependency(BaseTest.getResourceAsFile(this, "csv/dependencies.csv"));
        CsvAnalyzer instance = new CsvAnalyzer();
        instance.initialize(getSettings());
        instance.analyze(dep, engine);

        Dependency[] ds = engine.getDependencies();
        assertEquals("number of dependencies should be 1", 1, ds.length);

        Dependency d = ds[0];
        assertEquals(d.getName(), "LibreSSL");
        assertEquals(d.getVersion(), "2.9.1");
        assertEquals(d.getSha256sum(), "39e4dd856694dc10d564201e4549c46d2431601a2b10f3422507e24ccc8f62f8");
    }
}
