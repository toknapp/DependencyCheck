package org.owasp.dependencycheck.analyzer;

import java.io.FileFilter;

import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;

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
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }
}
