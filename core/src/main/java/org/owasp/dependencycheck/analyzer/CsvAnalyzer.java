package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.InvalidSettingException;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;


public class CsvAnalyzer implements Analyzer, FileTypeAnalyzer {
    private static final Logger LOGGER = LoggerFactory.getLogger(CsvAnalyzer.class);

    private boolean enabled = false;

    @Override
    public String getName() {
        return "CSV Analyzer";
    }

    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
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
                d.setVersion(record.get("version"));

                d.addEvidence(EvidenceType.VENDOR, source, "Vendor", record.get("vendor"), Confidence.HIGH);
                d.addEvidence(EvidenceType.PRODUCT, source, "Product", record.get("name"), Confidence.HIGH);
                d.addEvidence(EvidenceType.VERSION, source, "Version", record.get("version"), Confidence.HIGH);

                d.setActualFilePath(record.get("upstream"));
                d.setFilePath(record.get("upstream"));
                d.setPackagePath(record.get("upstream"));

                d.setSha256sum(record.get("sha256"));
                d.setSha1sum(record.get("sha1"));
                d.setMd5sum(record.get("md5"));

                if(record.isMapped("tarball")) {
                    d.setFileName(record.get("tarball"));
                } else {
                    d.setFileName(d.getActualFile().toPath().getFileName().toString());
                }

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

    @Override
    public void initialize(Settings settings) {
        final String key = Settings.KEYS.ANALYZER_CSV_ENABLED;
        try {
            this.enabled = settings.getBoolean(key, true);
        } catch (InvalidSettingException ex) {
            LOGGER.error("can't get setting: {}", key, ex);
        }
    }

    @Override
    public void prepare(Engine engine) throws InitializationException {
    }

    @Override
    public void close() throws Exception {
    }

    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public boolean accept(File file) {
        if(!this.enabled) return false;

        LOGGER.trace("accept? {}", file);

        String fn = file.toPath().getFileName().toString();
        if(fn.endsWith("csv") || fn.endsWith("tbl")) {
            LOGGER.debug("accepting: {}", file);
            return true;
        }

        return false;
    }
}
