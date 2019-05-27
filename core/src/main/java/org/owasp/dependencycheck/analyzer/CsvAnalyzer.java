package org.owasp.dependencycheck.analyzer;

import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.Charset;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;


public class CsvAnalyzer extends AbstractFileTypeAnalyzer {

    private static final String[] EXTENSIONS = {"csv", "tbl"};

    private static final FileFilter FILTER = FileFilterBuilder
        .newInstance().addExtensions(EXTENSIONS).build();

    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
    }

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    public String getName() {
        return "CSV Analyzer";
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CSV_ENABLED;
    }

    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        String source = dependency.getFileName();
        try {
            CSVFormat fmt = CSVFormat.newFormat(',')
                .withQuote('"')
                .withRecordSeparator('\n')
                .withFirstRecordAsHeader();
            CSVParser parser = CSVParser.parse(dependency.getActualFile(), Charset.defaultCharset(), fmt);
            for (CSVRecord record : parser) {
                Dependency d = new Dependency();

                d.setName(record.get("name"));
                d.addEvidence(EvidenceType.PRODUCT, source, "Product", record.get("name"), Confidence.HIGH);

                d.setVersion(record.get("version"));
                d.addEvidence(EvidenceType.VERSION, source, "Version", record.get("version"), Confidence.HIGH);

                d.setSha256sum(record.get("sha256"));

                engine.addDependency(d);
            }
        } catch (IOException ex) {
            throw new AnalysisException(ex);
        }
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }
}
